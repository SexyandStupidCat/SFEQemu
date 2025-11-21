-- Example Lua rules for QEMU syscall interception
--
-- Each function should be named: syscall_<syscall_name>
-- Function receives: num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8
-- Function should return: action, return_value
--   action = 0: continue with normal syscall execution
--   action = 1: skip normal execution, use provided return_value

-- Example 1: Log all write syscalls
function syscall_write(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    print(string.format("[Lua Hook] write(fd=%d, buf=0x%x, count=%d)", fd, buf, count))
    -- Return 0 to continue with normal execution
    return 0, 0
end

-- Example 2: Block certain open calls
function syscall_open(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    print(string.format("[Lua Hook] open(pathname=0x%x, flags=0x%x, mode=0x%x)", pathname, flags, mode))

    -- You could read the pathname and make decisions based on it
    -- For now, just log and continue
    return 0, 0
end

-- Example 3: Intercept getpid and return a fake PID
function syscall_getpid(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    print("[Lua Hook] getpid() intercepted, returning fake PID 12345")
    -- Return 1 to indicate we handled the syscall, with return value 12345
    return 1, 12345
end

-- Example 4: Monitor socket creation
function syscall_socket(num, domain, type, protocol, arg4, arg5, arg6, arg7, arg8)
    print(string.format("[Lua Hook] socket(domain=%d, type=%d, protocol=%d)", domain, type, protocol))
    -- Continue with normal execution
    return 0, 0
end

-- Example 5: Log all read operations
function syscall_read(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    print(string.format("[Lua Hook] read(fd=%d, buf=0x%x, count=%d)", fd, buf, count))
    return 0, 0
end

print("Lua syscall rules loaded successfully!")
