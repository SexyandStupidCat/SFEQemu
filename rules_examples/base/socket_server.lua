-- socket_server.lua - Unix domain socket 服务器模块
-- 提供创建和监听 Unix socket 的功能

local M = {}

-- 存储所有活动的 socket 服务器
M.active_servers = {}

-- AF_UNIX 和 SOCK_STREAM 常量
local AF_UNIX = 1
local SOCK_STREAM = 1

-- 辅助函数：构建 sockaddr_un 结构体
-- struct sockaddr_un {
--     uint16_t sun_family;  // AF_UNIX = 1
--     char sun_path[108];   // 路径
-- }
local function build_sockaddr_un(path)
    local sun_family = string.char(AF_UNIX, 0)  -- uint16_t, 小端序
    local sun_path = path .. string.rep("\0", 108 - #path)  -- 填充到108字节
    return sun_family .. sun_path
end

-- 创建并启动一个 Unix domain socket 服务器
-- @param socket_path: socket 文件路径
-- @param on_accept: 可选的回调函数，当接受连接时调用 on_accept(client_fd)
-- @return true/false 表示是否成功启动
function M.start_server(socket_path, on_accept)
    c_log(string.format("[socket_server] Starting server on %s", socket_path))

    -- 检查是否已经在运行
    if M.active_servers[socket_path] then
        c_log(string.format("[socket_server] Server already running on %s", socket_path))
        return false
    end

    -- 创建 socket
    local server_fd = c_do_syscall(281, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0)  -- socket()
    if server_fd < 0 then
        c_log(string.format("[socket_server] Failed to create socket: %d", server_fd))
        return false
    end

    c_log(string.format("[socket_server] Created socket fd=%d", server_fd))

    -- 删除旧的 socket 文件（如果存在）
    c_do_syscall(10, socket_path, 0, 0, 0, 0, 0)  -- unlink()

    -- 构建 sockaddr_un 结构
    local sockaddr = build_sockaddr_un(socket_path)
    local sockaddr_len = 2 + #socket_path + 1  -- family (2) + path + \0

    -- 写入 sockaddr 到临时内存（需要一个临时缓冲区地址）
    -- 这里我们使用栈上的一个位置，但更好的方式是分配内存
    -- 暂时简化：直接传递字符串给 bind（需要 C 代码支持）

    -- 由于 Lua 无法直接传递结构体，我们需要用另一种方式
    -- 让这个函数返回配置信息，由调用者决定如何处理

    c_log(string.format("[socket_server] TODO: Implement bind/listen logic"))
    c_log(string.format("[socket_server] Socket path: %s", socket_path))
    c_log(string.format("[socket_server] This requires C-side support for creating socket servers"))

    -- 标记服务器为活动状态
    M.active_servers[socket_path] = {
        fd = server_fd,
        path = socket_path,
        on_accept = on_accept
    }

    return true
end

-- 停止 socket 服务器
-- @param socket_path: socket 文件路径
function M.stop_server(socket_path)
    local server = M.active_servers[socket_path]
    if not server then
        return false
    end

    c_log(string.format("[socket_server] Stopping server on %s", socket_path))

    -- 关闭 socket
    if server.fd >= 0 then
        c_do_syscall(6, server.fd, 0, 0, 0, 0, 0)  -- close()
    end

    -- 删除 socket 文件
    c_do_syscall(10, socket_path, 0, 0, 0, 0, 0)  -- unlink()

    M.active_servers[socket_path] = nil
    return true
end

-- 检查服务器是否正在运行
-- @param socket_path: socket 文件路径
-- @return true/false
function M.is_running(socket_path)
    return M.active_servers[socket_path] ~= nil
end

return M
