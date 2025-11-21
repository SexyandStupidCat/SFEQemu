-- memory_demo.lua - Demonstrates memory access functions
-- This is a demonstration of c_g2h, c_h2g, and memory read/write functions

function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    c_log("=== Memory Access Demo ===")

    -- Example 1: g2h - guest to host translation
    if arg1 ~= 0 then
        c_log(string.format("Guest address: 0x%x", arg1))
        local host_addr = c_g2h(arg1)
        c_log(string.format("  -> Host address: %s", tostring(host_addr)))
    end

    -- Example 2: Read string from guest memory
    if arg1 ~= 0 then
        local str = c_read_guest_string(arg1, 256)
        c_log(string.format("  -> String at guest 0x%x: '%s'", arg1, str))
    end

    -- Example 3: Read 32-bit value
    if arg1 ~= 0 then
        local value32 = c_read_guest_u32(arg1)
        c_log(string.format("  -> u32 at guest 0x%x: 0x%08x", arg1, value32))
    end

    -- Example 4: Read 64-bit value
    if arg1 ~= 0 then
        local value64 = c_read_guest_u64(arg1)
        c_log(string.format("  -> u64 at guest 0x%x: 0x%016x", arg1, value64))
    end

    -- Call original syscall
    return c_do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
end

c_log("Loaded memory_demo.lua - memory access demonstration")
