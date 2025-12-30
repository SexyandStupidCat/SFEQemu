# Log Module 快速参考

## 快速开始

```lua
local log = require("rules_examples.base.log")

-- 启用文件日志（日志会保存到 rules_examples/log/ 目录）
log.enable_file_logging()

-- 使用日志
log.info("Hello, World!")
log.warn("Warning message")
log.error("Error message")
```

## 文件日志功能

### ✅ 现在可以写入文件了！

调用 `log.enable_file_logging()` 后：
- 日志会自动保存到 `rules_examples/log/` 目录
- 文件名格式：`qemu_lua_YYYYMMDD_HHMMSS.log`
- 每条日志带时间戳：`[2024-12-30 15:07:00] [INFO] message`
- 自动刷新，实时写入

### 三种输出模式

1. **仅控制台（默认）**
   ```lua
   log.info("Message")  -- 只输出到控制台
   ```

2. **同时输出到控制台和文件**
   ```lua
   log.enable_file_logging()
   log.info("Message")  -- 同时输出到控制台和文件
   ```

3. **仅文件（静默模式）**
   ```lua
   log.enable_file_logging()
   log.set_console_output(false)
   log.info("Message")  -- 只写入文件，不输出到控制台
   ```

## 常用函数

| 函数 | 功能 | 示例 |
|------|------|------|
| `enable_file_logging(dir, filename)` | 启用文件日志 | `log.enable_file_logging()` |
| `disable_file_logging()` | 禁用文件日志 | `log.disable_file_logging()` |
| `set_console_output(bool)` | 控制台输出开关 | `log.set_console_output(false)` |
| `info(fmt, ...)` | INFO 日志 | `log.info("PID: %d", pid)` |
| `warn(fmt, ...)` | WARN 日志 | `log.warn("Unusual value: 0x%x", val)` |
| `error(fmt, ...)` | ERROR 日志 | `log.error("Failed!")` |
| `syscall(name, fmt, ...)` | 系统调用日志 | `log.syscall("open", "path=%s", path)` |
| `count(name)` | 统计计数 | `log.count("total_calls")` |
| `show_stats()` | 显示统计 | `log.show_stats()` |

## 完整示例

```lua
local log = require("rules_examples.base.log")

-- 启用文件日志
local success, log_path = log.enable_file_logging()

if success then
    log.info("Logging to: %s", log_path)
end

-- 拦截系统调用
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    log.count("syscall_count")

    log.syscall("mysyscall", "num=%d, arg1=0x%x", num, arg1)

    -- 每100次显示统计
    if log.stats["syscall_count"] % 100 == 0 then
        log.show_stats()
    end

    return 0, 0
end

log.info("Script loaded")
```

## 日志输出示例

### 控制台输出
```
[Lua] [INFO] Script loaded
[Lua] [syscall:open] pathname=0x12345, flags=0x0
[Lua] [WARN] Unusual behavior detected
```

### 文件内容（rules_examples/log/qemu_lua_20241230_150700.log）
```
=== Log started at 2024-12-30 15:07:00 ===
[2024-12-30 15:07:00] [INFO] Script loaded
[2024-12-30 15:07:01] [syscall:open] pathname=0x12345, flags=0x0
[2024-12-30 15:07:02] [WARN] Unusual behavior detected
[2024-12-30 15:07:03] [INFO] Total calls: 100
=== Log ended at 2024-12-30 15:10:00 ===
```

## 更多信息

详细文档请参考：`rules_examples/base/LOG_README.md`
