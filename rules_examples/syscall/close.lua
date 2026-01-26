-- close.lua - Hook for close syscall
-- 用于在 fd 关闭时清理 fakefile 的 fd 映射，避免 fd 复用导致误判。

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")
local fakefile = require(rules_dir .. "plugins/fakefile")
local fdmap = require(rules_dir .. "base/fdmap")

function do_syscall(num, fd, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    local action, ret = fakefile.handle_close(num, fd, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    if action == 1 and type(ret) == "number" and ret == 0 then
        fdmap.clear(fd)
    end
    return action, ret
end
