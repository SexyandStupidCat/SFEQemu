-- kill.lua - Hook for kill syscall
--
-- 目标：
-- - 记录 kill 的目标与信号
-- - 默认仅拦截“可能把容器/PID1 一起干掉”的危险调用（通性问题）：
--     - kill(1, sig!=0)
--     - kill(-1, sig!=0)
--     - kill(0, SIGTERM/SIGKILL)  # 同进程组广播，常见于 reboot/shutdown 脚本
--
-- 说明：
-- - 返回值按 Linux 习惯使用负 errno（-EPERM = -1）
-- - sig==0 表示“仅探测是否有权限”，不拦截

local SIGKILL = 9
local SIGTERM = 15

local function log(fmt, ...)
    if type(c_log) ~= "function" then
        return
    end
    if select("#", ...) > 0 then
        c_log(string.format("[kill] " .. fmt, ...))
    else
        c_log("[kill] " .. tostring(fmt))
    end
end

function do_syscall(_num, pid, sig, arg3, arg4, arg5, arg6, arg7, arg8)
    pid = tonumber(pid) or 0
    sig = tonumber(sig) or 0

    log("pid=%d sig=%d", pid, sig)

    if sig == 0 then
        return 0, 0
    end

    -- 防御：避免固件的 reboot/shutdown 脚本把整个容器的 PID1 干掉，导致批量仿真“戛然而止”。
    if pid == 1 or pid == -1 then
        log("block dangerous kill: pid=%d sig=%d (EPERM)", pid, sig)
        return 1, -1
    end
    if pid == 0 and (sig == SIGTERM or sig == SIGKILL) then
        log("block group kill: pid=%d sig=%d (EPERM)", pid, sig)
        return 1, -1
    end

    return 0, 0
end

c_log("Loaded kill.lua")

