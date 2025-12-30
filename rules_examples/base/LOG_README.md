# Log Module 使用文档

`rules_examples/base/log.lua` 提供了一个统一的日志输出模块，用于在 Lua 规则脚本中进行日志记录。

## 功能特性

- 多级别日志输出 (DEBUG, INFO, WARN, ERROR)
- 格式化字符串支持
- 系统调用专用日志格式
- 十六进制值输出
- 简单的统计计数功能
- 表格数据转储（调试用）
- **文件日志输出** - 可将日志保存到文件
- **灵活的输出控制** - 可选择同时输出到控制台和/或文件

## 使用方法

### 1. 加载模块

```lua
local log = require("rules_examples.base.log")
```

### 2. 设置日志级别

```lua
-- 可选的日志级别
log.set_level(log.LEVEL.DEBUG)  -- 显示所有日志
log.set_level(log.LEVEL.INFO)   -- 显示 INFO 及以上（默认）
log.set_level(log.LEVEL.WARN)   -- 仅显示 WARN 和 ERROR
log.set_level(log.LEVEL.ERROR)  -- 仅显示 ERROR
```

### 3. 基本日志输出

```lua
-- 不同级别的日志
log.debug("This is a debug message")
log.info("This is an info message")
log.warn("This is a warning message")
log.error("This is an error message")

-- 格式化输出（类似 printf）
log.info("Process PID: %d, Name: %s", pid, name)
log.warn("Invalid value: 0x%x", value)
```

### 4. 系统调用日志

```lua
-- 专门用于记录系统调用信息
log.syscall("open", "pathname=0x%x, flags=0x%x, mode=0x%x",
            pathname_ptr, flags, mode)

-- 简单版本
log.syscall("getpid", "returning fake PID 99999")
```

### 5. 十六进制输出

```lua
log.hex("flags", 0x8915)
-- 输出: flags = 0x8915
```

### 6. 统计功能

```lua
-- 增加计数
log.count("syscall_open")
log.count("syscall_read")

-- 显示所有统计信息
log.show_stats()

-- 重置统计
log.reset_stats()
```

### 7. 分隔线

```lua
log.separator()           -- 默认：60个"-"
log.separator("=", 80)    -- 80个"="
```

### 8. 调试表格内容

```lua
local config = {
    name = "eth0",
    ip = "192.168.1.1",
    mac = "00:11:22:33:44:55"
}

log.dump_table(config)
```

### 9. 文件日志功能

#### 启用文件日志

```lua
-- 使用默认设置（日志目录：rules_examples/log，自动生成文件名）
local success, log_path = log.enable_file_logging()

if success then
    log.info("Log file created at: %s", log_path)
end

-- 或者指定自定义目录和文件名
log.enable_file_logging("/tmp/qemu_logs", "my_custom.log")
```

#### 禁用文件日志

```lua
log.disable_file_logging()
```

#### 控制输出目标

```lua
-- 同时输出到控制台和文件（默认）
log.set_console_output(true)
log.enable_file_logging()

-- 仅输出到文件，不输出到控制台
log.set_console_output(false)
log.enable_file_logging()

-- 仅输出到控制台，不输出到文件（默认行为）
log.set_console_output(true)
-- 不调用 enable_file_logging()
```

#### 文件日志特性

- 日志文件自动添加时间戳
- 每条日志包含格式：`[YYYY-MM-DD HH:MM:SS] [LEVEL] message`
- 自动刷新缓冲区，确保日志实时写入
- 支持追加模式，不会覆盖已有日志
- 文件开头和结尾自动添加分隔标记

## 完整示例

### 示例 1: 基本使用

```lua
local log = require("rules_examples.base.log")

-- 设置日志级别
log.set_level(log.LEVEL.INFO)

function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    -- 统计调用次数
    log.count("total_calls")

    -- 记录系统调用
    log.syscall("mysyscall", "arg1=0x%x, arg2=0x%x", arg1, arg2)

    -- 检查错误情况
    if arg1 == 0 then
        log.error("Invalid argument: arg1 is NULL")
        return 1, -1  -- 返回错误
    end

    -- 正常情况
    log.info("Processing syscall with arg1=0x%x", arg1)

    -- 显示统计（每100次调用）
    if log.stats["total_calls"] % 100 == 0 then
        log.separator()
        log.show_stats()
        log.separator()
    end

    return 0, 0  -- 继续执行原系统调用
end

log.info("Script loaded successfully")
```

### 示例 2: 使用文件日志

```lua
local log = require("rules_examples.base.log")

-- 启用文件日志
local success, log_path = log.enable_file_logging()

if success then
    log.info("Logging to file: %s", log_path)
end

-- 如果只想保存到文件，不输出到控制台
-- log.set_console_output(false)

function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    log.count("syscall_count")
    log.info("Syscall intercepted: num=%d", num)

    -- 日志会同时输出到控制台和文件

    return 0, 0
end

log.info("File logging example loaded")
```

## API 参考

### 日志级别

| 级别 | 常量 | 说明 |
|------|------|------|
| DEBUG | `log.LEVEL.DEBUG` | 调试信息 |
| INFO | `log.LEVEL.INFO` | 一般信息（默认） |
| WARN | `log.LEVEL.WARN` | 警告信息 |
| ERROR | `log.LEVEL.ERROR` | 错误信息 |

### 函数列表

| 函数 | 说明 |
|------|------|
| `log.set_level(level)` | 设置日志级别 |
| `log.debug(fmt, ...)` | 输出 DEBUG 日志 |
| `log.info(fmt, ...)` | 输出 INFO 日志 |
| `log.warn(fmt, ...)` | 输出 WARN 日志 |
| `log.error(fmt, ...)` | 输出 ERROR 日志 |
| `log.syscall(name, fmt, ...)` | 输出系统调用日志 |
| `log.hex(name, value)` | 输出十六进制值 |
| `log.separator(char, length)` | 输出分隔线 |
| `log.dump_table(table, indent)` | 转储表格内容 |
| `log.count(name)` | 增加统计计数 |
| `log.show_stats()` | 显示统计信息 |
| `log.reset_stats()` | 重置统计信息 |
| `log.enable_file_logging(dir, filename)` | 启用文件日志 |
| `log.disable_file_logging()` | 禁用文件日志 |
| `log.set_console_output(enabled)` | 设置是否输出到控制台 |

## 注意事项

1. 默认情况下，日志只输出到控制台（通过 `c_log()` 函数）
2. 调用 `log.enable_file_logging()` 后，日志会同时输出到控制台和文件
3. 使用 `log.set_console_output(false)` 可以禁用控制台输出，仅输出到文件
4. 格式化字符串使用 Lua 的 `string.format()` 语法
5. 统计信息存储在 `log.stats` 表中
6. 日志级别只影响输出，不影响程序执行
7. 文件日志自动刷新缓冲区，确保日志实时写入
8. 默认日志目录为 `rules_examples/log`，会自动创建

## 日志文件格式

启用文件日志后，日志文件格式如下：

```
=== Log started at 2024-12-19 15:30:00 ===
[2024-12-19 15:30:00] [INFO] Script loaded
[2024-12-19 15:30:01] [syscall:getpid] Intercepted
[2024-12-19 15:30:01] [INFO] Returning fake PID 99999
[2024-12-19 15:30:02] [WARN] Unusual behavior detected
[2024-12-19 15:30:03] [ERROR] Error occurred
=== Log ended at 2024-12-19 15:35:00 ===
```
