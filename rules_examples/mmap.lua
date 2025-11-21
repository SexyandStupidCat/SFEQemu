-- mmap.lua - Hook for mmap syscall
-- This script monitors memory mapping operations

function do_syscall(num, addr, length, prot, flags, fd, offset, arg7, arg8)
    local sec, nsec = c_get_timestamp()

    -- Log large memory mappings
    if length > 1048576 then  -- > 1MB
        c_log(string.format("[%d.%09d] Large mmap: addr=0x%x, length=%d bytes (%.2f MB)",
                           sec, nsec, addr, length, length / 1048576.0))
    end

    -- Log anonymous mappings
    if flags & 0x20 then  -- MAP_ANONYMOUS
        c_log(string.format("  -> Anonymous mapping"))
    end

    -- Continue with normal execution
    return 0, 0
end

c_log("Loaded mmap.lua")
