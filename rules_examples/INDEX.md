# Rules Examples 索引

欢迎使用 QEMU Lua 规则脚本示例库！

## 📋 目录结构

```
rules_examples/
├── base/                    # 基础模块和工具
│   ├── log.lua             # 日志模块（支持文件输出）
│   ├── LOG_README.md       # 日志模块完整文档
│   ├── QUICKSTART.md       # 日志模块快速入门
│   └── C_FUNCTIONS.md      # QEMU C 函数 API 文档
├── log/                     # 日志文件输出目录
├── CAPABILITIES.md          # 功能总览（从这里开始！）
└── [各种示例脚本]
```

## 🚀 快速开始

### 1. **先看这个！** [CAPABILITIES.md](CAPABILITIES.md)
- 📖 了解 Lua 脚本可以做什么
- 🔧 查看所有可用的 C 函数
- 💡 学习常用模式和最佳实践

### 2. 阅读文档
- **[base/C_FUNCTIONS.md](base/C_FUNCTIONS.md)** - 所有 C 函数的详细 API 文档
- **[base/LOG_README.md](base/LOG_README.md)** - Log 模块完整使用指南
- **[base/QUICKSTART.md](base/QUICKSTART.md)** - Log 模块快速入门

### 3. 运行示例
选择一个示例脚本运行，从简单到复杂：

## 📚 示例脚本分类

### 基础示例（修改后支持文件日志）

| 脚本 | 功能 | 难度 |
|------|------|------|
| **getpid.lua** | 拦截 getpid，返回假 PID | ⭐ |
| **socket.lua** | 监控 socket 调用，记录参数到文件 | ⭐ |
| **open.lua** | 监控文件打开，显示路径字符串 | ⭐ |
| **write.lua** | 监控写操作，显示缓冲区内容 | ⭐⭐ |
| **read.lua** | 监控读操作 | ⭐ |
| **mmap.lua** | 监控内存映射 | ⭐ |
| **ioctl.lua** | 监控 ioctl 调用（网络相关） | ⭐⭐ |

### Log 模块使用示例

| 脚本 | 功能 | 推荐 |
|------|------|------|
| **example_using_log.lua** | Log 模块基本使用 | ✅ 必看 |
| **example_file_logging.lua** | 文件日志功能演示 | ✅ 必看 |
| **ioctl_with_log.lua** | 使用 log 模块改进 ioctl | ⭐⭐ |

### 高级示例（展示 C 函数调用）

| 脚本 | 功能 | 难度 |
|------|------|------|
| **advanced_example.lua** | 综合示例：内存读取、寄存器访问、统计 | ⭐⭐⭐ |
| **register_example.lua** | 读取和显示所有 CPU 寄存器 | ⭐⭐⭐ |
| **memory_example.lua** | 内存操作和十六进制转储 | ⭐⭐⭐ |

## 🎯 按需求选择

### 我想要...

#### 📝 记录日志到文件
→ 使用 `log` 模块：
```lua
local log = require("rules_examples.base.log")
log.enable_file_logging()
log.info("Hello, World!")
```
参考：`example_file_logging.lua`

#### 🔍 读取内存中的字符串
→ 使用 `c_read_string(addr)` 或 `c_read_guest_bytes(addr, len)`
```lua
local path = c_read_string(pathname_ptr)
local data = c_read_guest_bytes(buf_ptr, count)
```
参考：`open.lua`, `write.lua`, `memory_example.lua`

#### 🎯 访问 CPU 寄存器
→ 使用 `c_get_reg()` 和 `c_list_regs()`
```lua
local pc, size, rc = c_get_reg("pc")
local regs = c_list_regs()
```
参考：`register_example.lua`

#### 🔧 修改系统调用行为
→ 在 `do_syscall()` 中返回不同的值
```lua
function do_syscall(num, ...)
    if num == 39 then  -- getpid
        return 1, 99999  -- 返回假 PID
    end
    return 0, 0  -- 继续执行原系统调用
end
```
参考：`getpid.lua`

#### 📊 统计系统调用
→ 使用 `log.count()` 和 `log.show_stats()`
```lua
log.count("open_calls")
log.show_stats()
```
参考：`advanced_example.lua`

## 💡 常用代码片段

### 基本框架
```lua
local log = require("rules_examples.base.log")
log.enable_file_logging()

function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    -- 你的代码
    return 0, 0  -- 继续执行原系统调用
end

log.info("Script loaded")
```

### 读取字符串参数
```lua
if pathname_ptr ~= 0 then
    local path = c_read_string(pathname_ptr)
    log.info("Path: %s", path)
end
```

### 读取缓冲区内容
```lua
if buf_ptr ~= 0 and count > 0 then
    local content = c_read_string(buf_ptr, count)
    log.info("Buffer: %s", content)
end
```

### 读取寄存器
```lua
local pc, size, rc = c_get_reg("pc")
if rc == 0 then
    log.info("PC = 0x%x", pc)
end
```

### 统计和显示
```lua
log.count("syscall_count")

if log.stats["syscall_count"] % 100 == 0 then
    log.show_stats()
end
```

## 📖 核心文档

### 必读文档（按顺序）
1. **[CAPABILITIES.md](CAPABILITIES.md)** - 功能总览，了解能做什么 ⭐⭐⭐
2. **[base/QUICKSTART.md](base/QUICKSTART.md)** - Log 模块快速入门 ⭐⭐
3. **[base/C_FUNCTIONS.md](base/C_FUNCTIONS.md)** - C 函数详细文档 ⭐⭐⭐
4. **[base/LOG_README.md](base/LOG_README.md)** - Log 模块完整文档 ⭐

## 🎓 学习路径

### 初级（1-2小时）
1. 阅读 `CAPABILITIES.md` 了解整体功能
2. 查看 `example_using_log.lua` 学习基本用法
3. 修改 `socket.lua` 或 `open.lua` 进行实验

### 中级（2-4小时）
1. 阅读 `base/C_FUNCTIONS.md` 了解所有 C 函数
2. 运行 `advanced_example.lua` 查看综合示例
3. 学习 `write.lua` 中的内存读取技巧

### 高级（4+小时）
1. 研究 `memory_example.lua` 的内存操作
2. 探索 `register_example.lua` 的寄存器访问
3. 创建自己的复杂规则脚本

## ⚠️ 重要提示

### ✅ 推荐做法
- 使用 log 模块记录到文件
- 只读取内存，避免修改
- 检查指针是否为 NULL (0)
- 限制读取长度避免过长

### ⚠️ 谨慎操作
- 修改寄存器值
- 写入客户机内存
- 修改系统调用参数

### ❌ 避免
- 在循环中进行大量内存操作
- 读取无效地址
- 修改关键系统调用的返回值（可能导致崩溃）

## 🔗 相关资源

- QEMU 源码：`linux-user/main.c`, `linux-user/syscall.c`
- Lua 官方文档：https://www.lua.org/manual/5.4/
- 系统调用参考：`man 2 syscall_name`

## 🐛 调试技巧

1. **启用 DEBUG 级别日志**
   ```lua
   log.set_level(log.LEVEL.DEBUG)
   ```

2. **检查返回值**
   ```lua
   local value, size, rc = c_get_reg("pc")
   if rc ~= 0 then
       log.error("Failed to get register")
   end
   ```

3. **使用十六进制转储**
   查看 `memory_example.lua` 中的 `hex_dump` 函数

4. **分步测试**
   从简单的日志开始，逐步添加复杂功能

## 📞 获取帮助

1. 查看相关文档
2. 运行类似的示例脚本
3. 检查 QEMU 源码中的函数实现
4. 使用 `log.debug()` 输出调试信息

---

**开始探索吧！** 🚀

建议从 [CAPABILITIES.md](CAPABILITIES.md) 开始，了解完整功能。
