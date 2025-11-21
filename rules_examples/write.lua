-- write.lua - Hook for write syscall
-- This script monitors write operations

function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    -- Log write operations
    c_log(string.format("write(fd=%d, buf=0x%x, count=%d)", fd, buf, count))

    -- Log large writes
    if count > 4096 then
        c_log(string.format("  -> Large write detected: %d bytes", count))
    end

    -- Block writes to stderr that are too large (example)
    if fd == 2 and count > 10240 then
        c_log("  -> Blocking large stderr write!")
        return 1, -1  -- Return error
    end

    -- Continue with normal execution
    return 0, 0
end

c_log("Loaded write.lua")
