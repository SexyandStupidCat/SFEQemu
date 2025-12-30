# QEMU Lua Syscall Rules V2 - 完全控制版本

## 核心概念

在这个版本中，**Lua 脚本完全控制系统调用的执行**：

1. 如果存在同名的 `.lua` 文件（如 `read.lua`），就执行 Lua 脚本
2. Lua 脚本可以调用 `c_do_syscall()` 来执行原始系统调用
3. Lua 脚本可以选择不调用原始系统调用，直接返回自定义值
4. Lua 脚本可以在系统调用前后做任何处理

## 关键特性

### c_do_syscall() 函数

这是一个 C 函数，可以在 Lua 中调用来执行原始的系统调用：

```lua
local ret = c_do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
```

**参数说明：**
- `num`: 系统调用号
- `arg1-arg8`: 系统调用的参数

**返回值：**
- 系统调用的返回值

## 脚本格式

每个脚本必须定义 `do_syscall` 函数：

```lua
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    -- 你的处理逻辑

    -- 可选：调用原始系统调用
    local ret = c_do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

    -- 返回值
    return ret
end
```

## 使用模式

### 模式 1: 监控（调用前后处理）

```lua
-- write.lua
function do_syscall(num, fd, buf, count, ...)
    -- 前处理
    c_log(string.format("Writing %d bytes to fd %d", count, fd))

    -- 调用原始系统调用
    local ret = c_do_syscall(num, fd, buf, count, ...)

    -- 后处理
    c_log(string.format("Wrote %d bytes", ret))

    return ret
end
```

### 模式 2: 修改结果

```lua
-- getpid.lua
function do_syscall(num, ...)
    -- 获取真实 PID
    local real_pid = c_do_syscall(num, ...)

    -- 返回修改后的值
    return real_pid + 10000
end
```

### 模式 3: 完全拦截（不调用原始）

```lua
-- socket.lua
function do_syscall(num, domain, type, protocol, ...)
    -- 完全阻止网络操作
    if domain == 2 then  -- AF_INET
        c_log("Blocked network socket creation")
        return -1  -- 返回错误
    end

    -- 其他情况调用原始
    return c_do_syscall(num, domain, type, protocol, ...)
end
```

### 模式 4: 统计和分析

```lua
-- read.lua
local stats = {count = 0, bytes = 0}

function do_syscall(num, fd, buf, count, ...)
    -- 执行原始调用
    local ret = c_do_syscall(num, fd, buf, count, ...)

    -- 统计
    if ret > 0 then
        stats.count = stats.count + 1
        stats.bytes = stats.bytes + ret

        if stats.count % 100 == 0 then
            c_log(string.format("Read stats: %d calls, %d bytes",
                               stats.count, stats.bytes))
        end
    end

    return ret
end
```

### 模式 5: 条件转发

```lua
-- open.lua
function do_syscall(num, pathname, flags, mode, ...)
    local is_write_mode = (flags & 3) ~= 0  -- O_WRONLY or O_RDWR

    if is_write_mode then
        c_log("Write access requested - checking permissions...")
        -- 这里可以添加额外的检查逻辑
    end

    -- 转发到原始调用
    return c_do_syscall(num, pathname, flags, mode, ...)
end
```

## 示例文件说明

### write.lua
演示基本的前后处理模式：
- 记录写入操作
- 调用原始 write
- 记录返回值

### getpid.lua
演示两种模式：
- `mode="modify"`: 调用原始并修改结果
- `mode="fake"`: 不调用原始，返回假值

### open.lua
演示条件拦截：
- 记录所有 open 调用
- 可配置是否阻止写入模式
- 默认转发到原始调用

### read.lua
演示统计收集：
- 追踪所有读取操作
- 累计读取的字节数
- 定期报告统计信息

### socket.lua
演示安全策略实施：
- 可配置阻止所有网络socket
- 默认阻止原始socket（需要root权限）
- Unix域socket允许通过

## 可用的 C 函数

### 系统调用执行

#### c_do_syscall(num, arg1-arg8)
调用原始系统调用

**示例：**
```lua
local ret = c_do_syscall(39)  -- getpid
local fd = c_do_syscall(2, pathname, flags, mode)  -- open
```

### 日志和时间

#### c_log(message)
输出日志消息

**示例：**
```lua
c_log("This is a log message")
c_log(string.format("Value: %d", value))
```

#### c_get_timestamp()
获取当前时间戳

**示例：**
```lua
local sec, nsec = c_get_timestamp()
c_log(string.format("Time: %d.%09d", sec, nsec))
```

### 地址转换

#### c_g2h(guest_addr)
将客户机地址转换为主机地址

**参数：**
- `guest_addr`: 客户机地址（整数）

**返回：**
- 主机地址（lightuserdata）

**示例：**
```lua
local host_addr = c_g2h(guest_addr)
```

#### c_h2g(host_addr)
将主机地址转换为客户机地址

**参数：**
- `host_addr`: 主机地址（lightuserdata）

**返回：**
- 客户机地址（整数），失败返回0

**示例：**
```lua
local guest_addr = c_h2g(host_addr)
```

### 内存读取

#### c_read_guest_string(guest_addr, max_len)
从客户机内存读取字符串

**参数：**
- `guest_addr`: 客户机地址（整数）
- `max_len`: 最大长度（可选，默认4096）

**返回：**
- `content, rc`
  - `content`: 字符串内容
  - `rc`: 0 表示成功，负数表示错误码（如 `-EFAULT`）

**示例：**
```lua
-- 读取write系统调用的缓冲区内容
local content, rc = c_read_guest_string(buf, count)
if rc ~= 0 then
    c_log(string.format("read_guest_string failed: %d", rc))
end
c_log(string.format("Writing: '%s'", content))
```

#### c_read_guest_u32(guest_addr)
从客户机内存读取32位无符号整数

**参数：**
- `guest_addr`: 客户机地址（整数）

**返回：**
- `value, rc`
  - `value`: 32位整数值（失败时为0）
  - `rc`: 0 表示成功，负数表示错误码

**示例：**
```lua
local value, rc = c_read_guest_u32(addr)
if rc ~= 0 then
    c_log(string.format("read_guest_u32 failed: %d", rc))
end
c_log(string.format("u32 value: 0x%08x", value))
```

#### c_read_guest_u64(guest_addr)
从客户机内存读取64位无符号整数

**参数：**
- `guest_addr`: 客户机地址（整数）

**返回：**
- `value, rc`
  - `value`: 64位整数值（失败时为0）
  - `rc`: 0 表示成功，负数表示错误码

**示例：**
```lua
local value, rc = c_read_guest_u64(addr)
if rc ~= 0 then
    c_log(string.format("read_guest_u64 failed: %d", rc))
end
c_log(string.format("u64 value: 0x%016x", value))
```

### 内存写入

#### c_write_guest_u32(guest_addr, value)
向客户机内存写入32位无符号整数

**参数：**
- `guest_addr`: 客户机地址（整数）
- `value`: 要写入的32位整数

**返回：**
- `rc`: 0 表示成功，负数表示错误码

**示例：**
```lua
local rc = c_write_guest_u32(addr, 0x12345678)
if rc ~= 0 then
    c_log(string.format("write_guest_u32 failed: %d", rc))
end
```

#### c_write_guest_u64(guest_addr, value)
向客户机内存写入64位无符号整数

**参数：**
- `guest_addr`: 客户机地址（整数）
- `value`: 要写入的64位整数

**返回：**
- `rc`: 0 表示成功，负数表示错误码

**示例：**
```lua
local rc = c_write_guest_u64(addr, 0x123456789abcdef0)
if rc ~= 0 then
    c_log(string.format("write_guest_u64 failed: %d", rc))
end
```

### 内存读写（字节）

#### c_read_guest_bytes(guest_addr, len)
从客户机内存读取指定长度的字节

**参数：**
- `guest_addr`: 客户机地址（整数）
- `len`: 读取长度（整数）

**返回：**
- `data, rc`
  - `data`: Lua 字符串（可包含 `\\0`）
  - `rc`: 0 表示成功，负数表示错误码

**别名：**
- `c_read_bytes(guest_addr, len)`

**示例：**
```lua
local data, rc = c_read_guest_bytes(buf, count)
if rc == 0 then
    c_log(string.format("read %d bytes", #data))
end
```

#### c_write_guest_bytes(guest_addr, data)
向客户机内存写入字节串

**参数：**
- `guest_addr`: 客户机地址（整数）
- `data`: Lua 字符串（可包含 `\\0`）

**返回：**
- `bytes_written, rc`
  - `bytes_written`: 成功写入的字节数（失败时为0）
  - `rc`: 0 表示成功，负数表示错误码

**别名：**
- `c_write_bytes(guest_addr, data)`

**示例：**
```lua
local n, rc = c_write_guest_bytes(buf, "hello\\0")
if rc ~= 0 then
    c_log(string.format("write_guest_bytes failed: %d", rc))
end
```

### 寄存器访问

#### c_list_regs()
列出当前 CPU 可用的寄存器列表（来自 gdbstub 的寄存器描述）

**返回：**
- `regs`: 数组，每项为 `{ num=..., name=..., feature=... }`

**示例：**
```lua
for i, r in ipairs(c_list_regs()) do
    c_log(string.format("reg[%d] %s = %d (%s)", i, r.name, r.num, r.feature))
end
```

#### c_get_reg(name_or_num)
读取寄存器值

**参数：**
- `name_or_num`: 寄存器名（字符串，如 `\"pc\"`、`\"x0\"`、`\"rax\"`）或 gdb regnum（整数）

**返回：**
- `value, size, rc`
  - `value`: `size <= 8` 时为整数；更大寄存器返回原始字节串（Lua string）
  - `size`: 寄存器字节数
  - `rc`: 0 表示成功，负数表示错误码

**示例：**
```lua
local val, size, rc = c_get_reg("pc")
if rc == 0 then
    c_log(string.format("pc(size=%d) = 0x%x", size, val))
end
```

#### c_set_reg(name_or_num, value_or_bytes)
写入寄存器值

**参数：**
- `name_or_num`: 寄存器名或 gdb regnum
- `value_or_bytes`:
  - 标量寄存器可传整数（将按寄存器宽度写入）
  - 大寄存器可传字节串（长度需匹配寄存器大小）

**返回：**
- `bytes_written, rc`
  - `bytes_written`: 写入的字节数（失败时为0）
  - `rc`: 0 表示成功，负数表示错误码

**示例：**
```lua
local n, rc = c_set_reg("x0", 0x1234)
if rc ~= 0 then
    c_log(string.format("set_reg failed: %d", rc))
end
```

## 高级技巧

### 1. 状态保持

使用局部变量保持状态：

```lua
local call_count = 0
local failed_calls = 0

function do_syscall(num, ...)
    call_count = call_count + 1

    local ret = c_do_syscall(num, ...)

    if ret < 0 then
        failed_calls = failed_calls + 1
    end

    return ret
end
```

### 2. 错误注入

模拟系统调用失败：

```lua
local failure_rate = 0.1  -- 10% 失败率

function do_syscall(num, ...)
    if math.random() < failure_rate then
        c_log("Injecting failure")
        return -5  -- -EIO
    end

    return c_do_syscall(num, ...)
end
```

### 3. 性能测量

测量系统调用执行时间：

```lua
function do_syscall(num, ...)
    local start_sec, start_nsec = c_get_timestamp()

    local ret = c_do_syscall(num, ...)

    local end_sec, end_nsec = c_get_timestamp()
    local elapsed_ns = (end_sec - start_sec) * 1000000000 + (end_nsec - start_nsec)

    c_log(string.format("Syscall took %d nanoseconds", elapsed_ns))

    return ret
end
```

### 4. 条件调试

只记录特定条件的调用：

```lua
function do_syscall(num, fd, buf, count, ...)
    -- 只记录大量写入
    if count > 1024 then
        c_log(string.format("Large write: %d bytes", count))
    end

    return c_do_syscall(num, fd, buf, count, ...)
end
```

## 与 V1 的区别

| 特性 | V1 (旧版) | V2 (新版) |
|------|----------|----------|
| 函数返回 | (action, return_value) | return_value |
| 调用原始 | 返回 action=0 | 调用 c_do_syscall() |
| 完全控制 | 否 | 是 |
| 脚本缓存 | 是 | 否（每次重新加载）|
| 灵活性 | 低 | 高 |

**V1 示例：**
```lua
function do_syscall(num, arg1, ...)
    -- 只能选择继续或返回值
    return 0, 0  -- 继续
    -- 或
    return 1, 99999  -- 返回假值
end
```

**V2 示例：**
```lua
function do_syscall(num, arg1, ...)
    -- 完全控制
    local ret = c_do_syscall(num, arg1, ...)  -- 可以调用原始
    return ret + 1  -- 可以修改结果
end
```

## 使用方法

```bash
# 1. 创建规则目录
mkdir my_rules

# 2. 复制示例或创建自己的规则
cp rules_examples_v2/write.lua my_rules/
cp rules_examples_v2/getpid.lua my_rules/

# 3. 运行 QEMU
./qemu-x86_64 --rules my_rules /path/to/program
```

## 注意事项

1. **性能**: 每次系统调用都会重新加载脚本（无缓存），适合开发和调试
2. **错误处理**: Lua 错误会被捕获，程序继续执行原始系统调用
3. **线程安全**: 使用线程局部存储，支持多线程
4. **调试**: 脚本修改后立即生效，无需重启 QEMU

## 最佳实践

1. **总是记录**: 使用 `c_log()` 记录重要操作
2. **错误检查**: 检查 `c_do_syscall()` 的返回值
3. **保持简单**: 避免复杂的 Lua 逻辑影响性能
4. **明确意图**: 用注释说明脚本的目的

## 调试技巧

### 检查脚本是否被加载

在脚本末尾添加：
```lua
c_log("Loaded xxx.lua")
```

### 验证参数

```lua
function do_syscall(num, arg1, arg2, ...)
    c_log(string.format("Args: num=%d, arg1=%d, arg2=%d", num, arg1, arg2))
    return c_do_syscall(num, arg1, arg2, ...)
end
```

### 测试错误处理

```lua
function do_syscall(num, ...)
    -- 故意制造错误测试
    error("Test error")
end
```

## 性能优化建议

如果需要更好的性能，可以：
1. 只为必要的系统调用创建脚本
2. 减少 Lua 中的计算量
3. 使用条件判断避免不必要的日志

## 总结

V2 版本提供了**完全的控制权**：
- ✅ 可以调用原始系统调用
- ✅ 可以修改返回值
- ✅ 可以完全拦截
- ✅ 可以在前后做任何处理
- ✅ 完全透明的控制流

这使得它非常适合：
- 安全研究
- 行为分析
- 调试和测试
- 性能监控
- 策略实施
