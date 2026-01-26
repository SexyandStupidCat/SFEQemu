-- socket.lua - Hook for socket syscall
-- This script monitors socket creation and logs parameters

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

    -- 打印并记录 socket 参数
    c_log(string.format("[socket] domain=%s, type=%s, protocol=%d", domain_str, type_str, protocol))

    -- 继续正常执行
    return 0, 0
end

c_log("Loaded socket.lua")
