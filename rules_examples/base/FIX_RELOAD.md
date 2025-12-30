# 修复日志模块重复加载问题

## 问题
脚本每次系统调用时都会重新加载，导致：
1. 日志文件中出现多个 `=== Log started ===` 头部
2. 控制台重复输出 "Loaded xxx.lua" 信息

## 根本原因
Lua 的模块系统在某些情况下会重新执行模块代码，导致模块的局部状态（如 `M.log_file`）被重置。

## 解决方案
使用全局变量 `_G._qemu_log_state` 来保持状态，而不是模块局部变量。

### 修改前
```lua
local M = {}
M.log_file = nil
M.log_to_file = false
-- 状态会在模块重新加载时丢失
```

### 修改后
```lua
if not _G._qemu_log_state then
    _G._qemu_log_state = {
        log_file = nil,
        log_to_file = false,
        stats = {},
        -- ... 其他状态
    }
end
local state = _G._qemu_log_state
-- 状态在全局范围内保持
```

## 效果
修改后，即使脚本被重新加载：
- ✅ 日志文件只打开一次
- ✅ 只输出一次 "Log started" 头部
- ✅ 统计数据保持连续
- ✅ 日志级别设置保持有效

## 测试
运行程序后，应该看到：
```
[Lua] [log] File logging enabled: ...  <- 只出现一次
[Lua] [INFO] Loaded open.lua           <- 只出现一次
[Lua] [syscall:open] ...
[Lua] [INFO]   Pathname: /lib/xxx
[Lua] [syscall:write] ...
[Lua] [INFO]   Buffer content: xxx
```

而不是重复的加载信息。
