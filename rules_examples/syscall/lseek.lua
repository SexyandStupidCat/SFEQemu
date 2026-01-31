-- lseek.lua - Hook for lseek syscall
-- 用于让 fakefile 的 read offset 与程序的 lseek 保持一致（仅对 fake fd 生效）。

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")
local fakefile = require(rules_dir .. "plugins/fakefile")
local fdmap = require(rules_dir .. "base/fdmap")
local mtd = require(rules_dir .. "base/mtd")

function do_syscall(num, fd, offset, whence, arg4, arg5, arg6, arg7, arg8)
    local action, ret = fakefile.handle_lseek(num, fd, offset, whence, arg4, arg5, arg6, arg7, arg8)
    if action == 1 then
        return action, ret
    end

    local info = fdmap.get(tonumber(fd) or -1)
    local path = (type(info) == "table" and info.path) or nil
    local action2, ret2 = mtd.handle_lseek(fd, path, offset, whence)
    if action2 == 1 then
        return action2, ret2
    end

    return 0, 0
end
