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

function do_syscall(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    -- 先执行 open 自己的逻辑（日志/统计），再交给 fakefile 做缺失资源补全
    local path = ""
    if pathname ~= 0 then
        local p, rc = c_read_string(pathname, 4096)
        if rc == 0 and p and p ~= "" then
            path = p
        end
    end

    if path ~= "" then
        c_log(string.format("[open] %s flags=0x%x mode=0x%x", path, flags, mode))
    else
        c_log(string.format("[open] pathname=0x%x flags=0x%x mode=0x%x", pathname, flags, mode))
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
