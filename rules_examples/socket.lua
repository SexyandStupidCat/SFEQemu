-- socket.lua - Hook for socket syscall
-- This script monitors socket creation

-- Socket domain constants
local AF_UNIX = 1
local AF_INET = 2
local AF_INET6 = 10

-- Socket type constants
local SOCK_STREAM = 1
local SOCK_DGRAM = 2
local SOCK_RAW = 3

function do_syscall(num, domain, type, protocol, arg4, arg5, arg6, arg7, arg8)
    local domain_names = {
        [AF_UNIX] = "AF_UNIX",
        [AF_INET] = "AF_INET",
        [AF_INET6] = "AF_INET6"
    }

    local type_names = {
        [SOCK_STREAM] = "SOCK_STREAM",
        [SOCK_DGRAM] = "SOCK_DGRAM",
        [SOCK_RAW] = "SOCK_RAW"
    }

    local domain_str = domain_names[domain] or string.format("UNKNOWN(%d)", domain)
    local type_str = type_names[type] or string.format("UNKNOWN(%d)", type)

    c_log(string.format("socket(%s, %s, %d)", domain_str, type_str, protocol))

    -- Block raw sockets (example)
    if type == SOCK_RAW then
        c_log("  -> Blocked attempt to create raw socket!")
        return 1, -1  -- Return error
    end

    -- Continue with normal execution
    return 0, 0
end

c_log("Loaded socket.lua")
