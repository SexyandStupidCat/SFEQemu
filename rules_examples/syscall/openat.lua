-- openat.lua - Hook for openat syscall
-- 适配大量现代程序使用 openat 的情况，交由 fakefile 框架补全缺失文件资源。

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")
local fakefile = require(rules_dir .. "plugins/fakefile")
local fdmap = require(rules_dir .. "base/fdmap")

local O_CREAT = 0x40
local AT_FDCWD = -100

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

local function classify_path(path)
    if type(path) ~= "string" or path == "" then
        return "file"
    end
    if path:match("^/dev/") then
        return "dev"
    end
    if path:match("^/proc/") then
        return "proc"
    end
    if path:match("^/sys/") then
        return "sys"
    end
    return "file"
end

function do_syscall(num, dirfd, pathname, flags, mode, arg5, arg6, arg7, arg8)
    -- 先执行 openat 自己的逻辑（日志/统计），再交给 fakefile 做缺失资源补全
    local path = ""
    local path_rc = -1
    if pathname ~= 0 then
        local p, rc = c_read_string(pathname, 4096)
        path_rc = tonumber(rc) or -1
        if rc == 0 and p and p ~= "" then
            path = p
        end
    end

    if path ~= "" then
        c_log(string.format("[openat] dirfd=%d %s flags=0x%x mode=0x%x", dirfd, path, flags, mode))
    else
        c_log(string.format("[openat] dirfd=%d pathname=0x%x flags=0x%x mode=0x%x", dirfd, pathname, flags, mode))
    end

    -- 额外输出一条更便于 grep/解析的目标路径日志
    if path ~= "" then
        c_log(string.format("[openat.target] %s", path))
    else
        c_log(string.format("[openat.target] (unreadable pathname=0x%x rc=%d)", pathname, path_rc))
    end

    -- 带创建语义的 openat（O_CREAT）不做任何干预：直接走原始 syscall。
    flags = math.floor(tonumber(flags) or 0)
    if (flags & O_CREAT) ~= 0 then
        -- openat(dirfd != AT_FDCWD, relative path) 无法可靠解析目标路径：跳过目录创建。
        -- 仅在绝对路径或 dirfd==AT_FDCWD 时尝试创建父目录。
        local can_handle = (type(path) == "string" and path ~= "" and (path:sub(1, 1) == "/" or dirfd == AT_FDCWD))
        if can_handle and type(c_mkdir_p) == "function" then
            local d = dirname(path)
            if not should_skip_dir(d) then
                local ok, rc = c_mkdir_p(d, 493) -- 0755
                if not ok then
                    c_log(string.format("[openat.creat] mkdir_p failed dir=%s rc=%s", tostring(d), tostring(rc)))
                end
            end
        end
        return 0, 0
    end

    local action, ret = fakefile.handle_openat(num, dirfd, pathname, flags, mode, arg5, arg6, arg7, arg8)

    if action == 1 and type(ret) == "number" and ret >= 0 and path ~= "" then
        fdmap.set(ret, {
            kind = classify_path(path),
            path = path,
            flags = flags or 0,
            mode = mode or 0,
            is_fake = fakefile.is_fake_fd(ret),
        })
    end

    return action, ret
end
