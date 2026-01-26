-- read.lua - Hook for read syscall
-- This script monitors read operations

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")
local fakefile = require(rules_dir .. "plugins/fakefile")
local fdmap = require(rules_dir .. "base/fdmap")

function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    -- 先做 read 自己的逻辑（日志），再交给 fakefile（命中时会拦截并写回 buf）
    c_log(string.format("[read] fd=%s buf=0x%x count=%d", fdmap.format(fd), buf, count))

    local action, retval = fakefile.handle_read(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    if action == 1 then
        return action, retval
    end

    -- Continue with normal execution
    return 0, 0
end

c_log("Loaded read.lua")
