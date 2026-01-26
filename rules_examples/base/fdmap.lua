-- fdmap.lua - 文件描述符(fd)映射表与展示工具
-- 目的：让 read/write 日志能打印“fd 对应的资源是什么”（文件名/Unix socket/标准流等）

local M = {}

if not _G._sfemu_fd_state then
    _G._sfemu_fd_state = {
        map = {}, -- fd(number) -> info(table)
    }
end

local state = _G._sfemu_fd_state

function M.set(fd, info)
    if type(fd) ~= "number" then
        return false
    end
    if fd < 0 then
        return false
    end
    if info == nil then
        state.map[fd] = nil
        return true
    end
    if type(info) ~= "table" then
        info = { kind = tostring(info) }
    end
    state.map[fd] = info
    return true
end

function M.get(fd)
    return state.map[fd]
end

function M.clear(fd)
    state.map[fd] = nil
end

local function describe_stdio(fd)
    if fd == 0 then
        return "stdin"
    end
    if fd == 1 then
        return "stdout"
    end
    if fd == 2 then
        return "stderr"
    end
    return nil
end

function M.describe(fd)
    local std = describe_stdio(fd)
    if std then
        return std
    end

    local info = state.map[fd]
    if type(info) ~= "table" then
        return "unknown"
    end

    if info.kind == "socket" then
        if type(info.path) == "string" and info.path ~= "" then
            return "socket:" .. info.path
        end
        if type(info.name) == "string" and info.name ~= "" then
            return "socket:" .. info.name
        end
        return "socket"
    end

    if type(info.path) == "string" and info.path ~= "" then
        return info.path
    end
    if type(info.name) == "string" and info.name ~= "" then
        return info.name
    end
    if type(info.kind) == "string" and info.kind ~= "" then
        return info.kind
    end
    if type(info.type) == "string" and info.type ~= "" then
        return info.type
    end
    return "unknown"
end

function M.format(fd)
    return string.format("%d(%s)", fd, M.describe(fd))
end

return M
