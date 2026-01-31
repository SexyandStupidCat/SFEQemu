-- bind.lua - Hook for bind syscall
--
-- 目标：
-- - 针对 AF_UNIX（sockaddr_un）在 bind() 时父目录不存在导致 ENOENT 的通性问题：
--     bind(fd, "/var/run/xxx.sock") -> -ENOENT
--   在不改变原始 bind 语义的前提下：
--     先 mkdir -p dirname(path)，再放行原始 syscall
--
-- 返回值：
--   (0, 0) = 不拦截，执行原始 syscall
--   (1, ret) = 拦截并返回 ret（本规则默认不拦截，只做前置目录补齐）

local AF_UNIX = 1

local function u16_le(b1, b2)
    return (b1 or 0) + ((b2 or 0) << 8)
end

local function u16_be(b1, b2)
    return ((b1 or 0) << 8) + (b2 or 0)
end

local function dirname(path)
    local p = tostring(path or "")
    if p == "" then
        return nil
    end
    if p ~= "/" then
        p = p:gsub("/+$", "")
    end
    if p == "" or p == "/" then
        return "/"
    end
    local d = p:match("^(.*)/[^/]+$") or ""
    if d == "" then
        if p:sub(1, 1) == "/" then
            return "/"
        end
        return "."
    end
    return d
end

local function should_skip_dir(d)
    if not d or d == "" or d == "." or d == "/" then
        return true
    end
    if d == "/proc" or d:match("^/proc/") then
        return true
    end
    if d == "/sys" or d:match("^/sys/") then
        return true
    end
    if d == "/dev" or d:match("^/dev/") then
        return true
    end
    return false
end

local function read_sockaddr_un_path(addr, addrlen)
    addr = tonumber(addr) or 0
    addrlen = tonumber(addrlen) or 0
    if addr == 0 or addrlen < 3 then
        return nil, "bad_addr"
    end

    local n = addrlen
    if n > 128 then
        n = 128
    end

    local bytes, rc = c_read_bytes(addr, n)
    if rc ~= 0 or type(bytes) ~= "string" or #bytes < 3 then
        return nil, "read_fail"
    end

    local b1 = string.byte(bytes, 1) or 0
    local b2 = string.byte(bytes, 2) or 0
    local fam_le = u16_le(b1, b2)
    local fam_be = u16_be(b1, b2)
    if fam_le ~= AF_UNIX and fam_be ~= AF_UNIX then
        return nil, "not_unix"
    end

    -- sockaddr_un.sun_path 从 offset=2 开始，C 字符串以 \0 结尾。
    local path_bytes = bytes:sub(3)
    if #path_bytes == 0 then
        return nil, "empty_path"
    end

    -- 抽象命名空间：首字节为 \0（不走文件系统），无需 mkdir。
    if string.byte(path_bytes, 1) == 0 then
        return nil, "abstract"
    end

    local z = path_bytes:find("\0", 1, true)
    local path = (z and path_bytes:sub(1, z - 1)) or path_bytes
    if path == "" then
        return nil, "empty_path"
    end
    return path, nil
end

function do_syscall(num, sockfd, addr, addrlen, arg4, arg5, arg6, arg7, arg8)
    local path, err = read_sockaddr_un_path(addr, addrlen)
    if not path then
        return 0, 0
    end

    if type(c_log) == "function" then
        c_log(string.format("[bind] unix path=%s", tostring(path)))
    end

    if type(c_mkdir_p) ~= "function" then
        return 0, 0
    end

    local d = dirname(path)
    if should_skip_dir(d) then
        return 0, 0
    end

    local ok, rc = c_mkdir_p(d, 493) -- 0755
    if not ok and type(c_log) == "function" then
        c_log(string.format("[bind] mkdir_p failed dir=%s rc=%s", tostring(d), tostring(rc)))
    end

    return 0, 0
end

c_log("Loaded bind.lua")

