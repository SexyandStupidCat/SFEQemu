-- reboot.lua - Hook for reboot syscall
--
-- 目标：
-- - 记录 reboot 调用
-- - 默认禁止真实 reboot（通性问题：某些固件会在初始化失败时触发 reboot，导致容器直接退出）
--
-- Linux reboot(2): reboot(magic1, magic2, cmd, arg)
-- 返回值：-EPERM = -1

local function log(fmt, ...)
    if type(c_log) ~= "function" then
        return
    end
    if select("#", ...) > 0 then
        c_log(string.format("[reboot] " .. fmt, ...))
    else
        c_log("[reboot] " .. tostring(fmt))
    end
end

function do_syscall(_num, magic1, magic2, cmd, arg4, arg5, arg6, arg7, arg8)
    magic1 = tonumber(magic1) or 0
    magic2 = tonumber(magic2) or 0
    cmd = tonumber(cmd) or 0

    log("blocked: magic1=0x%x magic2=0x%x cmd=0x%x", magic1 & 0xffffffff, magic2 & 0xffffffff, cmd & 0xffffffff)
    return 1, -1
end

c_log("Loaded reboot.lua")

