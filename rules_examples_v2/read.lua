-- read.lua - Hook for read syscall
-- This script tracks bytes read and can simulate slow I/O

local total_bytes_read = 0
local call_count = 0

function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    call_count = call_count + 1

    local sec, nsec = c_get_timestamp()
    c_log(string.format("[%d.%09d] read(fd=%d, count=%d) - call #%d",
                       sec, nsec, fd, count, call_count))

    -- Call the original syscall
    local ret = c_do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)

    -- Track successful reads
    if ret > 0 then
        total_bytes_read = total_bytes_read + ret
        c_log(string.format("  -> Read %d bytes (total: %d bytes)", ret, total_bytes_read))
    elseif ret == 0 then
        c_log("  -> EOF reached")
    else
        c_log(string.format("  -> Error: %d", ret))
    end

    -- Report statistics every 10 calls
    if call_count % 10 == 0 then
        c_log(string.format("=== Read Statistics: %d calls, %d bytes total ===",
                           call_count, total_bytes_read))
    end

    return ret
end

c_log("Loaded read.lua (v2) - tracking I/O statistics")
