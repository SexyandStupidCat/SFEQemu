-- getpid.lua - Hook for getpid syscall
-- This script demonstrates two approaches:
-- 1. Calling the original syscall and modifying the result
-- 2. Returning a completely fake value without calling the original

local mode = "modify" -- Change to "fake" to return fake PID without calling original

function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    if mode == "modify" then
        -- Approach 1: Call original and modify
        c_log("getpid() - calling original and modifying result")
        local real_pid = c_do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
        c_log(string.format("Real PID: %d, returning modified: %d", real_pid, real_pid + 10000))
        return real_pid + 10000
    else
        -- Approach 2: Don't call original, return fake value
        c_log("getpid() - returning fake PID without calling original")
        return 99999
    end
end

c_log("Loaded getpid.lua (v2)")
