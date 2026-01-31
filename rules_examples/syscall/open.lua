-- open.lua - Hook for open syscall
-- This script monitors file open operations and logs pathname
--
-- Return values:
--   (0, 0) = Don't intercept, let the original syscall run
--   (1, return_value) = Intercept and return the specified value

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")
local fakefile = require(rules_dir .. "plugins/fakefile")
local fdmap = require(rules_dir .. "base/fdmap")
local mtd = require(rules_dir .. "base/mtd")

local O_CREAT = 0x40
local ENOENT = -2

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

local function read_pathname(pathname)
    if pathname == 0 then
        return "", -1
    end

    -- 说明：c_read_string 内部会 lock_user(max_len)，如果 max_len 太大且跨越未映射页，
    -- 即使真实路径很短也可能读取失败（例如临近页边界的字符串指针）。
    -- 因此这里采用“从小到大”探测，尽量稳定拿到路径文本用于日志与规则匹配。
    local lens = { 256, 1024, 4096 }
    for _, max_len in ipairs(lens) do
        local p, rc = c_read_string(pathname, max_len)
        if rc == 0 and p and p ~= "" and p ~= "(null)" then
            return p, 0
        end
    end

    local _, rc = c_read_string(pathname, 256)
    return "", rc
end

function do_syscall(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    -- 先执行 open 自己的逻辑（日志/统计），再交给 fakefile 做缺失资源补全
    local path, path_rc = read_pathname(pathname)

    if path ~= "" then
        c_log(string.format("[open] %s flags=0x%x mode=0x%x", path, flags, mode))
    else
        c_log(string.format("[open] pathname=0x%x flags=0x%x mode=0x%x", pathname, flags, mode))
    end

    -- 额外输出一条更便于 grep/解析的目标路径日志
    if path ~= "" then
        c_log(string.format("[open.target] %s", path))
    else
        c_log(string.format("[open.target] (unreadable pathname=0x%x rc=%d)", pathname, path_rc or -1))
    end

    -- 带创建语义的 open（O_CREAT）不做任何干预：直接走原始 syscall。
    -- 说明：O_CREAT 只能创建“文件本身”，不会创建父目录；父目录缺失应由 bootstrap 提前补齐。
    flags = math.floor(tonumber(flags) or 0)
    if (flags & O_CREAT) ~= 0 then
        -- 如果父目录不存在，先递归创建父目录，再返回去执行原始 open。
        if path ~= "" and type(c_mkdir_p) == "function" then
            local d = dirname(path)
            if not should_skip_dir(d) then
                local ok, rc = c_mkdir_p(d, 493) -- 0755
                if not ok then
                    c_log(string.format("[open.creat] mkdir_p failed dir=%s rc=%s", tostring(d), tostring(rc)))
                end
            end
        end
        return 0, 0
    end

    -- /dev/nvram：强制走“安全 fd + Lua 侧仿真”，避免打开真实 nvram 设备导致 -EBUSY/-EINVAL。
    if path == "/dev/nvram" then
        if type(c_open_host) == "function" then
            local ret = c_open_host("/dev/zero", flags, mode)
            if type(ret) == "number" and ret >= 0 then
                fdmap.set(ret, {
                    kind = "dev",
                    path = "/dev/nvram",
                    flags = math.floor(tonumber(flags) or 0),
                    mode = math.floor(tonumber(mode) or 0),
                    is_fake = true,
                })
                c_log(string.format("[open.nvram] opened /dev/zero fd=%d (mapped as /dev/nvram)", ret))
                return 1, ret
            end
            if type(ret) == "number" then
                c_log(string.format("[open.nvram] c_open_host failed ret=%d", ret))
                return 1, ret
            end
        end
        -- 兜底：旧二进制无 c_open_host 时继续走原逻辑（可能失败）
    end

    -- /proc/mtd 与 /dev/mtd*：最小兜底（缺失时映射到 /dev/zero，并在 read() 时伪造内容）。
    if path == "/proc/mtd" or (type(path) == "string" and path:match("^/dev/mtd")) then
        if type(c_do_syscall) == "function" and type(c_open_host) == "function" then
            -- 先尝试真实 open（避免覆盖固件自带的 mtd 节点/挂载）
            local real_ret = c_do_syscall(num, pathname, flags, mode, arg4 or 0, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
            if type(real_ret) == "number" and real_ret >= 0 then
                fdmap.set(real_ret, {
                    kind = classify_path(path),
                    path = path,
                    flags = flags or 0,
                    mode = mode or 0,
                    is_fake = false,
                })
                if path == "/proc/mtd" then
                    mtd.mark_fd(real_ret)
                end
                return 1, real_ret
            end

            -- 仅在 ENOENT 时做兜底；其它错误码保持原样返回，避免掩盖真实问题。
            if type(real_ret) == "number" and real_ret ~= ENOENT then
                return 1, real_ret
            end

            local fd = c_open_host("/dev/zero", flags, mode)
            if type(fd) == "number" and fd >= 0 then
                fdmap.set(fd, {
                    kind = classify_path(path),
                    path = path,
                    flags = flags or 0,
                    mode = mode or 0,
                    is_fake = true,
                })
                if path == "/proc/mtd" then
                    mtd.mark_fd(fd)
                end
                c_log(string.format("[open.mtd] mapped %s to /dev/zero fd=%d", path, fd))
                return 1, fd
            end
            if type(fd) == "number" then
                c_log(string.format("[open.mtd] c_open_host failed ret=%d", fd))
                return 1, fd
            end
        end
    end

    local action, ret = fakefile.handle_open(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)

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
