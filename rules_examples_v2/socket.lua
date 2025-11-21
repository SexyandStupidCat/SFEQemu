-- socket.lua - Hook for socket syscall
-- This script demonstrates blocking syscalls without calling the original

-- Socket domain constants
local AF_UNIX = 1
local AF_INET = 2
local AF_INET6 = 10

-- Socket type constants
local SOCK_STREAM = 1
local SOCK_DGRAM = 2
local SOCK_RAW = 3

-- Configuration
local block_network = false  -- Set to true to block all network sockets
local block_raw_sockets = true  -- Block raw sockets (usually requires root)

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

    -- Block all network sockets if configured
    if block_network and (domain == AF_INET or domain == AF_INET6) then
        c_log("  -> Network socket blocked by policy")
        return -1  -- Return error without calling original
    end

    -- Always block raw sockets
    if block_raw_sockets and type == SOCK_RAW then
        c_log("  -> Raw socket blocked (requires root)")
        return -1  -- Return EPERM
    end

    -- Forward to original syscall
    local ret = c_do_syscall(num, domain, type, protocol, arg4, arg5, arg6, arg7, arg8)
    c_log(string.format("  -> Created socket fd: %d", ret))
    return ret
end

c_log("Loaded socket.lua (v2) - network policy enforcement")
