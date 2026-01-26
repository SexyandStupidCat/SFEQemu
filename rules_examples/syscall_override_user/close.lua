-- close.lua - 本地 override：清理 netlink fd 标记 + 复用已有 close 规则
--
-- 说明：
-- - socket.lua 会把“需要兼容的 netlink fd”记录到 _sfemu_netlink_fds；
-- - 为避免 fd 复用导致误判，这里在 close(fd) 时清理该标记；
-- - 同时尽量复用已有 close 规则（如果存在 syscall_override/close.lua，则优先复用它）。

local function unmark_netlink(fd)
    local m = rawget(_G, "_sfemu_netlink_fds")
    if type(m) ~= "table" then
        return
    end
    m[fd] = nil
end

local base_do = nil
do
    local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
    local rules_dir = script_dir:gsub("syscall_override_user/?$", ""):gsub("syscall_override/?$", ""):gsub("syscall/?$", "")

    local candidates = {
        rules_dir .. "syscall_override/close.lua",
        rules_dir .. "syscall/close.lua",
    }

    for _, p in ipairs(candidates) do
        local env = setmetatable({}, { __index = _G })
        local chunk = loadfile(p, "t", env)
        if chunk then
            pcall(chunk)
            if type(env.do_syscall) == "function" then
                base_do = env.do_syscall
                break
            end
        end
    end
end

function do_syscall(num, fd, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    unmark_netlink(fd)
    if type(base_do) == "function" then
        return base_do(num, fd, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    end
    return 0, 0
end

