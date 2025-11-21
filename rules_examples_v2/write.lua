-- write.lua - Hook for write syscall
-- This script demonstrates how to call the original syscall with c_do_syscall()

function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    -- Log before the syscall
    c_log(string.format("[Before] write(fd=%d, buf=0x%x, count=%d)", fd, buf, count))

    -- Call the original syscall
    local ret = c_do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)

    -- Log after the syscall
    c_log(string.format("[After] write returned: %d", ret))

    -- Return the result from the original syscall
    return ret
end

c_log("Loaded write.lua (v2 - with c_do_syscall)")
