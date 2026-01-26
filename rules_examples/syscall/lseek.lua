-- lseek.lua - Hook for lseek syscall
-- 用于让 fakefile 的 read offset 与程序的 lseek 保持一致（仅对 fake fd 生效）。

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")
local fakefile = require(rules_dir .. "plugins/fakefile")

function do_syscall(num, fd, offset, whence, arg4, arg5, arg6, arg7, arg8)
    return fakefile.handle_lseek(num, fd, offset, whence, arg4, arg5, arg6, arg7, arg8)
end
