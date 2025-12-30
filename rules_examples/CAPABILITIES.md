# Lua 脚本功能总览

## 是的！Lua 脚本可以调用 QEMU 中的 C 函数！

QEMU 已经注册了大量的 C 函数供 Lua 脚本调用，提供了强大的功能。

## 可用的 C 函数分类

### 📝 日志输出
- `c_log(message)` - 输出日志信息
- `c_get_timestamp()` - 获取时间戳

### 💾 内存读取
- `c_read_string(addr, max_len)` - 读取字符串
- `c_read_guest_u32(addr)` - 读取 32 位整数
- `c_read_guest_u64(addr)` - 读取 64 位整数
- `c_read_guest_bytes(addr, len)` - 读取原始字节

### ✏️ 内存写入
- `c_write_guest_u32(addr, value)` - 写入 32 位整数
- `c_write_guest_u64(addr, value)` - 写入 64 位整数
- `c_write_guest_bytes(addr, data)` - 写入原始字节

### 🎯 寄存器操作
- `c_list_regs()` - 列出所有寄存器
- `c_get_reg(name)` - 读取寄存器值
- `c_set_reg(name, value)` - 设置寄存器值

### 🔄 地址转换
- `c_g2h(guest_addr)` - 客户机地址转主机地址
- `c_h2g(host_addr)` - 主机地址转客户机地址

### 🔧 系统调用
- `c_do_syscall(num, ...)` - 执行原始系统调用

## 文档和示例

### 📚 详细文档
- **[C_FUNCTIONS.md](base/C_FUNCTIONS.md)** - 完整的 C 函数 API 文档
- **[LOG_README.md](base/LOG_README.md)** - Log 模块完整文档
- **[QUICKSTART.md](base/QUICKSTART.md)** - Log 模块快速入门

### 💡 示例脚本

#### 基础示例
- **open.lua** - 拦截 open 系统调用，打印文件路径
- **write.lua** - 拦截 write 系统调用，打印缓冲区内容
- **socket.lua** - 拦截 socket 系统调用，记录参数
- **getpid.lua** - 拦截 getpid，返回假的 PID

#### 使用 Log 模块
- **example_using_log.lua** - 基本使用示例
- **example_file_logging.lua** - 文件日志示例
- **ioctl_with_log.lua** - 实际应用示例

#### 高级示例
- **advanced_example.lua** - 综合示例，展示多种功能
- **register_example.lua** - 寄存器操作示例
- **memory_example.lua** - 内存操作和十六进制转储

## 快速开始

### 1. 简单的内存读取示例

```lua
local log = require("rules_examples.base.log")
log.enable_file_logging()

function do_syscall(num, pathname, flags, mode, ...)
    if num == 2 then  -- open
        -- 读取路径字符串
        local path = c_read_string(pathname)
        log.info("Opening: %s", path)
    end
    return 0, 0
end
```

### 2. 读取寄存器示例

```lua
local log = require("rules_examples.base.log")

function do_syscall(num, ...)
    -- 读取 PC 寄存器
    local pc, size, rc = c_get_reg("pc")
    if rc == 0 then
        log.info("PC = 0x%x", pc)
    end

    -- 列出所有寄存器
    local regs = c_list_regs()
    for _, name in ipairs(regs) do
        local value, size, rc = c_get_reg(name)
        if rc == 0 and type(value) == "number" then
            log.info("%s = 0x%x", name, value)
        end
    end

    return 0, 0
end
```

### 3. 内存读写示例

```lua
function do_syscall(num, fd, buf, count, ...)
    if num == 1 then  -- write
        -- 读取缓冲区内容
        local content = c_read_string(buf, count)
        log.info("Writing: %s", content)

        -- 读取原始字节
        local raw_bytes = c_read_guest_bytes(buf, count)

        -- 读取特定位置的整数
        local value = c_read_guest_u32(buf)
        log.info("First u32: 0x%x", value)
    end
    return 0, 0
end
```

## 重要注意事项

### ✅ 可以做的事情
- 读取系统调用参数指向的内存
- 读取和记录寄存器值
- 记录日志到文件
- 执行原始系统调用获取真实结果
- 读取字符串、整数、原始字节

### ⚠️ 需要谨慎的操作
- 修改寄存器（可能导致程序崩溃）
- 写入客户机内存（可能破坏数据）
- 修改系统调用参数（需要充分理解影响）

### ❌ 限制
- 某些操作只能在系统调用上下文中使用
- 地址必须有效，否则可能导致段错误
- 不同架构的寄存器名称不同

## 常用模式

### 模式 1: 监控和日志记录
```lua
-- 只记录，不修改
function do_syscall(num, ...)
    log.syscall("xxx", "parameters...")
    return 0, 0  -- 继续执行原系统调用
end
```

### 模式 2: 修改参数
```lua
-- 读取、修改、继续执行
function do_syscall(num, pathname, ...)
    local path = c_read_string(pathname)
    if path == "/etc/passwd" then
        -- 可以修改内存中的路径
        -- c_write_guest_bytes(pathname, "/tmp/fake\0")
    end
    return 0, 0
end
```

### 模式 3: 伪造返回值
```lua
-- 不执行真实系统调用，返回伪造结果
function do_syscall(num, ...)
    if num == 39 then  -- getpid
        return 1, 99999  -- 返回假的 PID
    end
    return 0, 0
end
```

### 模式 4: 调用真实系统调用
```lua
-- 执行真实系统调用并处理结果
function do_syscall(num, arg1, arg2, ...)
    local result = c_do_syscall(num, arg1, arg2, ...)
    log.info("Real result: %d", result)
    return 1, result  -- 返回真实结果
end
```

## 更多资源

- 查看 `base/C_FUNCTIONS.md` 了解所有函数的详细文档
- 查看 `base/LOG_README.md` 了解日志模块的完整功能
- 运行示例脚本学习实际用法
- 查看 QEMU 源码 `linux-user/syscall.c` 了解实现细节

## 架构差异

不同 CPU 架构的寄存器名称不同：

| 架构 | PC 寄存器 | 返回值寄存器 | 参数寄存器 |
|------|-----------|--------------|-----------|
| x86_64 | rip | rax | rdi, rsi, rdx, ... |
| ARM64 | pc | x0 | x0-x7 |
| ARM32 | pc | r0 | r0-r3 |
| RISCV | pc | a0 | a0-a7 |

使用 `c_list_regs()` 可以查看当前架构的所有寄存器。
