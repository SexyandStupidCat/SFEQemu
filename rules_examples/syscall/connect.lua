-- connect.lua - Hook for connect syscall
-- 主要用于 Unix domain socket：当目标 socket 资源缺失时，交由 fakefile 框架补全。

local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
local rules_dir = script_dir:gsub("syscall/?$", "")
local fakefile = require(rules_dir .. "plugins/fakefile")
local fdmap = require(rules_dir .. "base/fdmap")

-- Socket 常量
local AF_UNIX = 1
local AF_INET = 2
local AF_INET6 = 10

local function read_u16_le(bytes)
    if not bytes or #bytes < 2 then
        return nil
    end
    return string.byte(bytes, 1) + (string.byte(bytes, 2) << 8)
end

local function read_unix_socket_path(sockaddr_addr)
    local family_bytes, rc = c_read_bytes(sockaddr_addr, 2)
    if rc ~= 0 then
        return nil, nil
    end

    local family = read_u16_le(family_bytes)
    if family ~= AF_UNIX then
        return nil, family
    end

    local path, rc2 = c_read_string(sockaddr_addr + 2, 108)
    if rc2 ~= 0 then
        return nil, family
    end

    path = (path or ""):match("^([^%z]*)")
    return path, family
end

local function read_inet_socket_info(sockaddr_addr)
    local sockaddr_bytes, rc = c_read_bytes(sockaddr_addr, 16)
    if rc ~= 0 or not sockaddr_bytes or #sockaddr_bytes < 16 then
        return nil, nil, nil
    end

    local family = read_u16_le(sockaddr_bytes:sub(1, 2))
    local port = (string.byte(sockaddr_bytes, 3) << 8) + string.byte(sockaddr_bytes, 4)
    local ip = string.format("%d.%d.%d.%d",
        string.byte(sockaddr_bytes, 5),
        string.byte(sockaddr_bytes, 6),
        string.byte(sockaddr_bytes, 7),
        string.byte(sockaddr_bytes, 8))
    return ip, port, family
end

function do_syscall(num, sockfd, addr, addrlen, arg4, arg5, arg6, arg7, arg8)
    -- 先做 connect 自己的逻辑（日志/维护 fd 表），再交给 fakefile 做缺失补全
    if addr ~= 0 then
        local family_bytes, rc = c_read_bytes(addr, 2)
        if rc == 0 then
            local family = read_u16_le(family_bytes)

            if family == AF_UNIX then
                local socket_path = read_unix_socket_path(addr)
                if socket_path and socket_path ~= "" then
                    fdmap.set(sockfd, { kind = "socket", path = socket_path })
                    c_log(string.format("[connect] fd=%s -> %s", fdmap.format(sockfd), socket_path))
                else
                    fdmap.set(sockfd, { kind = "socket" })
                    c_log(string.format("[connect] fd=%s -> AF_UNIX", fdmap.format(sockfd)))
                end

            elseif family == AF_INET then
                local ip, port = read_inet_socket_info(addr)
                if ip and port then
                    fdmap.set(sockfd, { kind = "socket", name = string.format("inet %s:%d", ip, port) })
                    c_log(string.format("[connect] fd=%s -> %s:%d", fdmap.format(sockfd), ip, port))
                else
                    fdmap.set(sockfd, { kind = "socket", name = "inet" })
                    c_log(string.format("[connect] fd=%s -> AF_INET", fdmap.format(sockfd)))
                end

            elseif family == AF_INET6 then
                fdmap.set(sockfd, { kind = "socket", name = "inet6" })
                c_log(string.format("[connect] fd=%s -> AF_INET6", fdmap.format(sockfd)))
            else
                fdmap.set(sockfd, { kind = "socket", name = string.format("af=%d", family or -1) })
                c_log(string.format("[connect] fd=%s -> AF(%s)", fdmap.format(sockfd), tostring(family)))
            end
        end
    end

    return fakefile.handle_connect(num, sockfd, addr, addrlen, arg4, arg5, arg6, arg7, arg8)
end
