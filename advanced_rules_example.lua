-- Advanced Lua rules example with C function integration
--
-- This demonstrates how to use C helper functions from Lua

-- Global variables for statistics
local syscall_stats = {}
local blocked_calls = 0

-- Helper function to initialize stats for a syscall
local function init_stats(name)
    if not syscall_stats[name] then
        syscall_stats[name] = {
            count = 0,
            last_timestamp = 0
        }
    end
end

-- Helper function to update stats
local function update_stats(name)
    init_stats(name)
    syscall_stats[name].count = syscall_stats[name].count + 1
    local sec, nsec = c_get_timestamp()
    syscall_stats[name].last_timestamp = sec
end

-- Helper function to log with timestamp
local function log_with_time(message)
    local sec, nsec = c_get_timestamp()
    c_log(string.format("[%d.%09d] %s", sec, nsec, message))
end

-- Example 1: Advanced write monitoring with statistics
function syscall_write(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    update_stats("write")

    -- Log large writes
    if count > 4096 then
        log_with_time(string.format("Large write detected: fd=%d, count=%d bytes", fd, count))
    end

    -- Block writes to stderr (fd=2) that are too large
    if fd == 2 and count > 10240 then
        c_log("Blocking large stderr write!")
        blocked_calls = blocked_calls + 1
        return 1, -1  -- Return error
    end

    return 0, 0  -- Continue normally
end

-- Example 2: File access control
function syscall_open(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    update_stats("open")

    log_with_time(string.format("open(pathname=0x%x, flags=0x%x, mode=0x%x)",
                                pathname, flags, mode))

    -- You could read the pathname using c_read_string if it was properly implemented
    -- local path = c_read_string(pathname)
    -- if path:match("/etc/passwd") then
    --     c_log("Blocked attempt to open /etc/passwd")
    --     return 1, -13  -- Return -EACCES
    -- end

    return 0, 0
end

function syscall_openat(num, dirfd, pathname, flags, mode, arg5, arg6, arg7, arg8)
    update_stats("openat")
    log_with_time(string.format("openat(dirfd=%d, pathname=0x%x, flags=0x%x, mode=0x%x)",
                                dirfd, pathname, flags, mode))
    return 0, 0
end

-- Example 3: Network monitoring
function syscall_socket(num, domain, type, protocol, arg4, arg5, arg6, arg7, arg8)
    update_stats("socket")

    local domain_names = {
        [1] = "AF_UNIX",
        [2] = "AF_INET",
        [10] = "AF_INET6"
    }

    local type_names = {
        [1] = "SOCK_STREAM",
        [2] = "SOCK_DGRAM",
        [3] = "SOCK_RAW"
    }

    local domain_str = domain_names[domain] or string.format("UNKNOWN(%d)", domain)
    local type_str = type_names[type] or string.format("UNKNOWN(%d)", type)

    log_with_time(string.format("socket(%s, %s, %d)", domain_str, type_str, protocol))

    -- Block raw sockets (requires root anyway, but good example)
    if type == 3 then  -- SOCK_RAW
        c_log("Blocked attempt to create raw socket!")
        blocked_calls = blocked_calls + 1
        return 1, -1  -- Return error
    end

    return 0, 0
end

function syscall_connect(num, sockfd, addr, addrlen, arg4, arg5, arg6, arg7, arg8)
    update_stats("connect")
    log_with_time(string.format("connect(sockfd=%d, addr=0x%x, addrlen=%d)",
                                sockfd, addr, addrlen))
    return 0, 0
end

-- Example 4: Process management monitoring
function syscall_fork(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    update_stats("fork")
    log_with_time("fork() called")
    return 0, 0
end

function syscall_clone(num, flags, stack, parent_tid, child_tid, tls, arg6, arg7, arg8)
    update_stats("clone")
    log_with_time(string.format("clone(flags=0x%x, stack=0x%x)", flags, stack))
    return 0, 0
end

function syscall_execve(num, filename, argv, envp, arg4, arg5, arg6, arg7, arg8)
    update_stats("execve")
    log_with_time(string.format("execve(filename=0x%x, argv=0x%x, envp=0x%x)",
                                filename, argv, envp))
    return 0, 0
end

-- Example 5: Memory operation monitoring
function syscall_mmap(num, addr, length, prot, flags, fd, offset, arg7, arg8)
    update_stats("mmap")

    -- Log large memory mappings
    if length > 1048576 then  -- > 1MB
        log_with_time(string.format("Large mmap: addr=0x%x, length=%d bytes (%.2f MB)",
                                    addr, length, length / 1048576.0))
    end

    return 0, 0
end

function syscall_brk(num, addr, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    update_stats("brk")
    return 0, 0
end

-- Example 6: I/O monitoring
function syscall_read(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    update_stats("read")

    -- Log reads from stdin
    if fd == 0 then
        log_with_time(string.format("read from stdin: %d bytes", count))
    end

    return 0, 0
end

-- Periodic statistics reporting
local last_report_time = 0
local report_interval = 10  -- Report every 10 seconds

function report_statistics()
    local sec, nsec = c_get_timestamp()

    if sec - last_report_time >= report_interval then
        c_log("=== Syscall Statistics ===")
        for name, stats in pairs(syscall_stats) do
            c_log(string.format("  %s: %d calls", name, stats.count))
        end
        c_log(string.format("  Total blocked calls: %d", blocked_calls))
        c_log("========================")
        last_report_time = sec
    end
end

-- Hook every syscall to update statistics report
-- This is called by wrapping it in other syscall functions

-- You could also add a global hook that runs for every syscall:
-- Just call report_statistics() in your syscall handlers

c_log("Advanced Lua rules loaded with C integration!")
c_log(string.format("Report interval: %d seconds", report_interval))
