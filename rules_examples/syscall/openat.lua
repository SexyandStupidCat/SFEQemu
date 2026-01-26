-- openat.lua - Hook for openat syscall
-- 适配大量现代程序使用 openat 的情况，交由 fakefile 框架补全缺失文件资源。

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

function do_syscall(num, dirfd, pathname, flags, mode, arg5, arg6, arg7, arg8)
    -- 先执行 openat 自己的逻辑（日志/统计），再交给 fakefile 做缺失资源补全
    local path = ""
    if pathname ~= 0 then
        local p, rc = c_read_string(pathname, 4096)
        if rc == 0 and p and p ~= "" then
            path = p
        end
    end

    if path ~= "" then
        c_log(string.format("[openat] dirfd=%d %s flags=0x%x mode=0x%x", dirfd, path, flags, mode))
    else
        c_log(string.format("[openat] dirfd=%d pathname=0x%x flags=0x%x mode=0x%x", dirfd, pathname, flags, mode))
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
