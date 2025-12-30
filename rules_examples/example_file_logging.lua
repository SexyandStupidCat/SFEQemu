-- example_file_logging.lua - 展示如何使用文件日志功能
-- 这个示例展示如何将日志写入文件

local log = require("rules_examples.base.log")

-- 设置日志级别
log.set_level(log.LEVEL.INFO)

-- 启用文件日志到 rules_examples/log 目录
-- 第一个参数：日志目录（可选，默认为 "rules_examples/log"）
-- 第二个参数：日志文件名（可选，默认为自动生成的时间戳文件名）
local success, log_path = log.enable_file_logging()

if success then
    log.info("File logging enabled at: %s", log_path)
else
    log.error("Failed to enable file logging")
end

-- 你也可以指定自定义路径和文件名：
-- log.enable_file_logging("/tmp/qemu_logs", "my_custom.log")

-- 如果只想输出到文件，不输出到控制台：
-- log.set_console_output(false)

-- 示例：拦截 getpid 系统调用
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    log.count("getpid_calls")

    log.info("getpid() intercepted")
    log.syscall("getpid", "Returning fake PID 99999")

    -- 每10次调用显示统计
    if log.stats["getpid_calls"] % 10 == 0 then
        log.separator()
        log.show_stats()
        log.separator()
    end

    -- 返回假的 PID
    return 1, 99999
end

log.info("example_file_logging.lua loaded")
log.separator("=", 50)

-- 注意：在脚本结束时，你可以选择关闭文件日志
-- log.disable_file_logging()
