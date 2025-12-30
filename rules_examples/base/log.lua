-- log.lua - 日志工具模块
-- 提供统一的日志输出接口，支持不同级别和格式化输出

-- 使用全局表来保持状态（避免模块重新加载时状态丢失）
if not _G._qemu_log_state then
    _G._qemu_log_state = {
        log_file = nil,
        log_file_path = nil,
        log_dir = nil,
        log_to_file = false,
        log_to_console = true,
        current_level = 2,  -- INFO level
        stats = {},
    }
end

local state = _G._qemu_log_state
local M = {}

-- 日志级别定义
M.LEVEL = {
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
}

-- 日志级别名称
local LEVEL_NAMES = {
    [M.LEVEL.DEBUG] = "DEBUG",
    [M.LEVEL.INFO]  = "INFO",
    [M.LEVEL.WARN]  = "WARN",
    [M.LEVEL.ERROR] = "ERROR",
}

-- 访问器：提供对状态的访问
M.stats = state.stats

-- 属性访问
function M.get_current_level()
    return state.current_level
end

-- 设置日志级别
function M.set_level(level)
    state.current_level = level
end

-- 启用文件日志
-- log_dir: 日志目录路径，默认为 "rules_examples/log"
-- filename: 日志文件名，默认为 "qemu_lua_YYYYMMDD_HHMMSS.log"
function M.enable_file_logging(log_dir, filename)
    -- 如果已经启用了文件日志，不重复打开
    if state.log_to_file and state.log_file then
        return true, state.log_file_path
    end

    state.log_dir = log_dir or "rules_examples/log"

    -- 创建日志目录
    os.execute("mkdir -p " .. state.log_dir)

    -- 生成默认文件名（如果未指定）
    if not filename then
        filename = string.format("qemu_lua_%s.log", os.date("%Y%m%d_%H%M%S"))
    end

    local log_path = state.log_dir .. "/" .. filename
    state.log_file_path = log_path

    -- 打开日志文件（追加模式）
    state.log_file = io.open(log_path, "a")

    if state.log_file then
        state.log_to_file = true
        -- 写入日志头
        state.log_file:write(string.format("=== Log started at %s ===\n", os.date("%Y-%m-%d %H:%M:%S")))
        state.log_file:flush()

        if state.log_to_console then
            c_log(string.format("[log] File logging enabled: %s", log_path))
        end

        return true, log_path
    else
        if state.log_to_console then
            c_log(string.format("[log] ERROR: Failed to open log file: %s", log_path))
        end
        return false, nil
    end
end

-- 禁用文件日志
function M.disable_file_logging()
    if state.log_file then
        state.log_file:write(string.format("=== Log ended at %s ===\n", os.date("%Y-%m-%d %H:%M:%S")))
        state.log_file:close()
        state.log_file = nil
    end
    state.log_to_file = false
end

-- 设置是否同时输出到控制台
function M.set_console_output(enabled)
    state.log_to_console = enabled
end

-- 写入日志到文件和/或控制台
local function write_log(message)
    -- 添加时间戳
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local log_line = string.format("[%s] %s", timestamp, message)

    -- 输出到控制台
    if state.log_to_console then
        c_log(message)
    end

    -- 输出到文件
    if state.log_to_file and state.log_file then
        state.log_file:write(log_line .. "\n")
        state.log_file:flush()  -- 立即刷新，确保日志写入
    end
end

-- 通用日志输出函数
local function log_message(level, fmt, ...)
    if level >= state.current_level then
        local level_name = LEVEL_NAMES[level] or "UNKNOWN"
        local msg

        if select('#', ...) > 0 then
            -- 有额外参数，使用 string.format
            msg = string.format(fmt, ...)
        else
            -- 没有额外参数，直接使用 fmt
            msg = fmt
        end

        write_log(string.format("[%s] %s", level_name, msg))
    end
end

-- DEBUG 级别日志
function M.debug(fmt, ...)
    log_message(M.LEVEL.DEBUG, fmt, ...)
end

-- INFO 级别日志
function M.info(fmt, ...)
    log_message(M.LEVEL.INFO, fmt, ...)
end

-- WARN 级别日志
function M.warn(fmt, ...)
    log_message(M.LEVEL.WARN, fmt, ...)
end

-- ERROR 级别日志
function M.error(fmt, ...)
    log_message(M.LEVEL.ERROR, fmt, ...)
end

-- 格式化输出系统调用信息
function M.syscall(name, fmt, ...)
    local msg
    if select('#', ...) > 0 then
        msg = string.format(fmt, ...)
    else
        msg = fmt or ""
    end

    if msg ~= "" then
        write_log(string.format("[syscall:%s] %s", name, msg))
    else
        write_log(string.format("[syscall:%s]", name))
    end
end

-- 格式化输出十六进制数值
function M.hex(name, value)
    write_log(string.format("%s = 0x%x", name, value))
end

-- 输出分隔线（用于区分不同部分的日志）
function M.separator(char, length)
    char = char or "-"
    length = length or 60
    write_log(string.rep(char, length))
end

-- 输出表格内容（调试用）
function M.dump_table(t, indent)
    indent = indent or 0
    local prefix = string.rep("  ", indent)

    for k, v in pairs(t) do
        if type(v) == "table" then
            write_log(string.format("%s%s = {", prefix, tostring(k)))
            M.dump_table(v, indent + 1)
            write_log(string.format("%s}", prefix))
        else
            write_log(string.format("%s%s = %s", prefix, tostring(k), tostring(v)))
        end
    end
end

-- 简单的性能统计辅助函数
function M.count(name)
    state.stats[name] = (state.stats[name] or 0) + 1
end

function M.show_stats()
    if next(state.stats) == nil then
        write_log("No statistics recorded")
        return
    end

    M.separator("=")
    write_log("Statistics:")
    M.separator("-")

    for name, count in pairs(state.stats) do
        write_log(string.format("  %s: %d", name, count))
    end

    M.separator("=")
end

function M.reset_stats()
    state.stats = {}
    M.stats = state.stats
end

return M
