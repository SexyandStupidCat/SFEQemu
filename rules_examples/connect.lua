-- connect.lua - Hook for connect syscall
-- 当连接 Unix domain socket 失败时，自动创建 socket 并模拟连接成功

-- Socket 常量
local AF_UNIX = 1
local AF_INET = 2
local AF_INET6 = 10

-- 已创建的 socket 路径列表
local created_sockets = {}

-- 虚拟连接的文件描述符映射 (virtual_fd -> real_fd)
local virtual_connections = {}
local next_virtual_fd = 1000  -- 从 1000 开始分配虚拟 fd

-- 辅助函数：从 sockaddr 读取 Unix domain socket 路径
-- struct sockaddr_un {
--     uint16_t sun_family;  // 2 bytes
--     char sun_path[108];   // 108 bytes
-- }
local function read_unix_socket_path(sockaddr_addr)
    -- 读取 sun_family (2 bytes)
    local family_bytes, rc = c_read_bytes(sockaddr_addr, 2)
    if rc ~= 0 or not family_bytes then
        return nil, nil
    end

    local family = string.byte(family_bytes, 1) + (string.byte(family_bytes, 2) << 8)
    if family ~= AF_UNIX then
        return nil, family
    end

    -- 读取 sun_path (最多 108 bytes)
    local path, rc2 = c_read_string(sockaddr_addr + 2, 108)
    if rc2 ~= 0 then
        return nil, family
    end

    -- 去掉尾部的空字符
    if path then
        path = path:match("^([^%z]*)")
    end

    return path, family
end

-- 辅助函数：从 sockaddr_in 读取 IP 和端口
local function read_inet_socket_info(sockaddr_addr)
    -- 读取完整的 sockaddr_in (16 bytes)
    local sockaddr_bytes, rc = c_read_bytes(sockaddr_addr, 16)
    if rc ~= 0 or not sockaddr_bytes then
        return nil, nil
    end

    -- 解析 sin_family (2 bytes)
    local family = string.byte(sockaddr_bytes, 1) + (string.byte(sockaddr_bytes, 2) << 8)

    -- 解析 sin_port (2 bytes, 网络字节序 = 大端序)
    local port = (string.byte(sockaddr_bytes, 3) << 8) + string.byte(sockaddr_bytes, 4)

    -- 解析 sin_addr (4 bytes)
    local ip = string.format("%d.%d.%d.%d",
        string.byte(sockaddr_bytes, 5),
        string.byte(sockaddr_bytes, 6),
        string.byte(sockaddr_bytes, 7),
        string.byte(sockaddr_bytes, 8))

    return ip, port, family
end

-- 辅助函数：创建 Unix domain socket 服务器
local function create_socket_server(socket_path)
    c_log(string.format("[connect] Creating socket server: %s", socket_path))

    -- 1. 创建 socket
    local server_fd = c_do_syscall(281, AF_UNIX, 1, 0, 0, 0, 0)  -- socket(AF_UNIX, SOCK_STREAM, 0)
    if server_fd < 0 then
        c_log(string.format("[connect] Failed to create socket: error=%d", server_fd))
        return false
    end

    c_log(string.format("[connect] Created server socket fd=%d", server_fd))

    -- 2. 删除旧的 socket 文件
    c_do_syscall(10, socket_path, 0, 0, 0, 0, 0)  -- unlink()

    -- 3. Bind socket
    -- 需要构建 sockaddr_un 结构体并写入内存
    -- 这里我们简化：直接尝试 bind（假设 C 代码会处理路径字符串）

    -- 注意：Lua 无法直接构建内存结构传递给 bind
    -- 我们需要另一种方案：使用 c_write_bytes 创建临时结构

    c_log(string.format("[connect] Socket server setup for %s (bind/listen not fully implemented in Lua)", socket_path))

    -- 标记为已创建
    created_sockets[socket_path] = {
        fd = server_fd,
        path = socket_path
    }

    return true
end

-- 辅助函数：创建虚拟的已连接 socket
local function create_virtual_connection(socket_path)
    -- 创建一个管道作为虚拟连接
    -- 这里我们返回一个虚拟的 fd，让程序认为连接成功了
    local virtual_fd = next_virtual_fd
    next_virtual_fd = next_virtual_fd + 1

    virtual_connections[virtual_fd] = {
        path = socket_path,
        type = "unix",
        connected = true
    }

    c_log(string.format("[connect] Created virtual connection, fd=%d for %s", virtual_fd, socket_path))
    return virtual_fd
end

-- 主处理函数
function do_syscall(num, sockfd, addr, addrlen, arg4, arg5, arg6, arg7, arg8)
    if addr == 0 then
        c_log("[connect] addr is NULL, passing through")
        return 0, 0
    end

    -- 尝试读取地址族
    local family_bytes, rc = c_read_bytes(addr, 2)
    if rc ~= 0 or not family_bytes then
        c_log("[connect] Failed to read address family, passing through")
        return 0, 0
    end

    local family = string.byte(family_bytes, 1) + (string.byte(family_bytes, 2) << 8)

    if family == AF_UNIX then
        -- Unix domain socket
        local socket_path, _ = read_unix_socket_path(addr)

        if socket_path and socket_path ~= "" then
            c_log(string.format("[connect] sockfd=%d, family=AF_UNIX, path=%s", sockfd, socket_path))

            -- 先让原始 connect 尝试
            local result = c_do_syscall(num, sockfd, addr, addrlen, 0, 0, 0)

            if result < 0 then
                -- connect 失败，可能是文件不存在
                c_log(string.format("[connect] Original connect failed with error %d", result))

                -- 检查是否是我们关心的路径（比如 /var/cfm_socket）
                if socket_path:match("^/var/") or socket_path:match("^/tmp/") then
                    c_log(string.format("[connect] Socket path not found, will try to set up server: %s", socket_path))

                    -- 尝试创建 socket 服务器
                    if not created_sockets[socket_path] then
                        create_socket_server(socket_path)
                    end

                    -- 简化方案：直接返回成功，让程序认为连接建立了
                    -- 这样程序可以继续运行，即使实际的 socket 服务器没有完全设置好
                    c_log(string.format("[connect] Returning success for %s", socket_path))
                    return 1, 0  -- 返回成功
                end

                -- 不是我们关心的路径，返回原始错误
                return 1, result
            else
                -- connect 成功
                c_log(string.format("[connect] Connect succeeded, fd=%d", result))
                return 1, result
            end
        else
            c_log("[connect] Could not read socket path, passing through")
        end

    elseif family == AF_INET then
        -- IPv4 socket
        local ip, port, _ = read_inet_socket_info(addr)
        if ip and port then
            c_log(string.format("[connect] sockfd=%d, family=AF_INET, addr=%s:%d", sockfd, ip, port))
        else
            c_log(string.format("[connect] sockfd=%d, family=AF_INET", sockfd))
        end

    elseif family == AF_INET6 then
        -- IPv6 socket
        c_log(string.format("[connect] sockfd=%d, family=AF_INET6", sockfd))

    else
        -- 未知地址族
        c_log(string.format("[connect] sockfd=%d, family=UNKNOWN(%d)", sockfd, family))
    end

    -- 默认：让原始 syscall 执行
    return 0, 0
end
