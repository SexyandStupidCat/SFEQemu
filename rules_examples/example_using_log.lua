-- example_using_log.lua - 展示如何使用 base/log.lua 模块
-- 这是一个使用示例，展示如何在规则脚本中调用 log 函数

-- 加载 log 模块
local log = require("rules_examples.base.log")

-- 设置日志级别（可选）
-- log.set_level(log.LEVEL.DEBUG)  -- 显示所有日志
log.set_level(log.LEVEL.INFO)      -- 默认：显示 INFO 及以上级别

-- 示例：拦截 open 系统调用
function do_syscall(num, pathname_ptr, flags, mode, arg4, arg5, arg6, arg7, arg8)
    -- 统计调用次数
    log.count("open_calls")

    -- 不同级别的日志输出
    log.debug("Debug message: open syscall details")
    log.info("Intercepting open() syscall")

    -- 格式化输出系统调用信息
    log.syscall("open", "pathname=0x%x, flags=0x%x, mode=0x%x",
                pathname_ptr, flags, mode)

    -- 输出十六进制值
    log.hex("flags", flags)

    -- 条件日志
    if flags == 0 then
        log.warn("Opening file with flags = 0, this is unusual")
    end

    -- 模拟某些错误情况
    if pathname_ptr == 0 then
        log.error("NULL pointer passed to open()!")
        return 1, -14  -- EFAULT
    end

    -- 显示统计信息（每10次调用显示一次）
    if log.stats["open_calls"] % 10 == 0 then
        log.separator()
        log.show_stats()
        log.separator()
    end

    -- 继续执行原系统调用
    return 0, 0
end

-- 脚本加载时的日志
log.info("example_using_log.lua loaded successfully")
log.separator("=", 50)
