-- read.lua - Hook for read syscall
-- This script monitors read operations

function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    -- Log read operations from stdin
    if fd == 0 then
        c_log(string.format("read from stdin: buf=0x%x, count=%d", buf, count))
    end

    -- Continue with normal execution
    return 0, 0
end

c_log("Loaded read.lua")
