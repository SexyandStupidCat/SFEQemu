-- getpid.lua - Hook for getpid syscall
-- This script returns a fake PID

function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    c_log("getpid() intercepted - returning fake PID 99999")

    -- Return fake PID
    return 1, 99999
end

c_log("Loaded getpid.lua")
