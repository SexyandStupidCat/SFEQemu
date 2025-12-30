# QEMU C 函数 API 文档

在 Lua 脚本中可以调用 QEMU 中注册的 C 函数。以下是所有可用的 C 函数列表。

## 日志输出

### `c_log(message)`
输出日志信息到 stderr

**参数:**
- `message` (string): 要输出的日志消息

**示例:**
```lua
c_log("Hello from Lua!")
c_log(string.format("Value: %d", 123))
```

## 时间相关

### `c_get_timestamp()`
获取当前时间戳

**返回值:**
- `seconds` (number): 秒数
- `nanoseconds` (number): 纳秒数

**示例:**
```lua
local sec, nsec = c_get_timestamp()
c_log(string.format("Timestamp: %d.%09d", sec, nsec))
```

## 内存读取函数

### `c_read_string(guest_addr, max_len)`
从客户机内存读取字符串（别名：`c_read_guest_string`）

**参数:**
- `guest_addr` (number): 客户机内存地址
- `max_len` (number, 可选): 最大读取长度，默认 4096

**返回值:**
- `string`: 读取的字符串内容

**示例:**
```lua
local path = c_read_string(pathname_ptr)
log.info("Path: %s", path)

-- 限制读取长度
local buf_content = c_read_string(buf_ptr, 100)
```

### `c_read_guest_u32(guest_addr)`
从客户机内存读取 32 位无符号整数

**参数:**
- `guest_addr` (number): 客户机内存地址

**返回值:**
- `value` (number): 读取的 32 位整数

**示例:**
```lua
local value = c_read_guest_u32(addr)
log.info("Value at 0x%x: 0x%x", addr, value)
```

### `c_read_guest_u64(guest_addr)`
从客户机内存读取 64 位无符号整数

**参数:**
- `guest_addr` (number): 客户机内存地址

**返回值:**
- `value` (number): 读取的 64 位整数

**示例:**
```lua
local value = c_read_guest_u64(addr)
log.info("64-bit value: 0x%x", value)
```

### `c_read_guest_bytes(guest_addr, length)`
从客户机内存读取原始字节（别名：`c_read_bytes`）

**参数:**
- `guest_addr` (number): 客户机内存地址
- `length` (number): 要读取的字节数

**返回值:**
- `bytes` (string): 读取的原始字节数据

**示例:**
```lua
local data = c_read_guest_bytes(addr, 16)
-- data 是包含 16 字节的字符串
```

## 内存写入函数

### `c_write_guest_u32(guest_addr, value)`
向客户机内存写入 32 位无符号整数

**参数:**
- `guest_addr` (number): 客户机内存地址
- `value` (number): 要写入的 32 位整数

**返回值:**
- `result` (number): 0 表示成功，负数表示错误

**示例:**
```lua
local rc = c_write_guest_u32(addr, 0x12345678)
if rc == 0 then
    log.info("Write successful")
end
```

### `c_write_guest_u64(guest_addr, value)`
向客户机内存写入 64 位无符号整数

**参数:**
- `guest_addr` (number): 客户机内存地址
- `value` (number): 要写入的 64 位整数

**返回值:**
- `result` (number): 0 表示成功，负数表示错误

**示例:**
```lua
local rc = c_write_guest_u64(addr, 0x123456789abcdef)
```

### `c_write_guest_bytes(guest_addr, data)`
向客户机内存写入原始字节（别名：`c_write_bytes`）

**参数:**
- `guest_addr` (number): 客户机内存地址
- `data` (string): 要写入的原始字节数据

**返回值:**
- `result` (number): 0 表示成功，负数表示错误

**示例:**
```lua
local data = "\x00\x01\x02\x03"
local rc = c_write_guest_bytes(addr, data)
```

## 寄存器操作

### `c_list_regs()`
列出所有可用的寄存器名称

**返回值:**
- `reg_list` (table): 寄存器名称数组

**示例:**
```lua
local regs = c_list_regs()
for i, name in ipairs(regs) do
    log.info("Register %d: %s", i, name)
end
```

### `c_get_reg(reg_name_or_num)`
读取寄存器的值

**参数:**
- `reg_name_or_num` (string|number): 寄存器名称（如 "pc", "x0"）或 GDB 寄存器编号

**返回值:**
- `value` (number|string): 寄存器值（≤8 字节返回整数，更大的返回原始字节串）
- `size` (number): 寄存器大小（字节数）
- `rc` (number): 结果码（0 表示成功）

**示例:**
```lua
-- 按名称读取
local pc_value, size, rc = c_get_reg("pc")
if rc == 0 then
    log.info("PC = 0x%x (size: %d bytes)", pc_value, size)
end

-- 按编号读取
local value, size, rc = c_get_reg(32)

-- 读取大寄存器（如向量寄存器）
local v0_bytes, size, rc = c_get_reg("v0")
-- v0_bytes 是原始字节串
```

### `c_set_reg(reg_name_or_num, value)`
写入寄存器的值

**参数:**
- `reg_name_or_num` (string|number): 寄存器名称或 GDB 寄存器编号
- `value` (number|string): 要写入的值（整数或原始字节串）

**返回值:**
- `bytes_written` (number): 实际写入的字节数
- `rc` (number): 结果码（0 表示成功）

**示例:**
```lua
-- 写入整数值
local written, rc = c_set_reg("x0", 0x1234)
if rc == 0 then
    log.info("Wrote %d bytes to x0", written)
end

-- 写入原始字节
local raw_data = "\x00\x01\x02\x03\x04\x05\x06\x07"
local written, rc = c_set_reg("v0", raw_data)
```

## 地址转换

### `c_g2h(guest_addr)`
将客户机地址转换为主机地址（Guest to Host）

**参数:**
- `guest_addr` (number): 客户机虚拟地址

**返回值:**
- `host_addr` (number): 主机地址

**示例:**
```lua
local host_addr = c_g2h(guest_addr)
log.info("Guest 0x%x -> Host 0x%x", guest_addr, host_addr)
```

### `c_h2g(host_addr)`
将主机地址转换为客户机地址（Host to Guest）

**参数:**
- `host_addr` (number): 主机地址

**返回值:**
- `guest_addr` (number): 客户机虚拟地址

**示例:**
```lua
local guest_addr = c_h2g(host_addr)
```

## 系统调用

### `c_do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6)`
执行原始的系统调用

**参数:**
- `num` (number): 系统调用号
- `arg1-arg6` (number): 系统调用参数

**返回值:**
- `result` (number): 系统调用返回值

**示例:**
```lua
-- 执行原始的 getpid 系统调用
local real_pid = c_do_syscall(39)  -- 39 是 getpid 的系统调用号
log.info("Real PID: %d", real_pid)
```

## 完整示例

### 示例 1: 读取和修改文件路径

```lua
local log = require("rules_examples.base.log")
log.enable_file_logging()

function do_syscall(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    -- 读取路径字符串
    local path = c_read_string(pathname)
    log.info("Opening: %s", path)

    -- 如果是 /etc/hosts，可以修改内存中的路径
    if path == "/etc/hosts" then
        log.warn("Redirecting /etc/hosts to /tmp/fake_hosts")
        -- 写入新路径（注意：需要确保有足够空间）
        -- c_write_guest_bytes(pathname, "/tmp/fake_hosts\0")
    end

    return 0, 0
end
```

### 示例 2: 读取和修改寄存器

```lua
local log = require("rules_examples.base.log")

function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    -- 读取 PC 寄存器
    local pc, size, rc = c_get_reg("pc")
    if rc == 0 then
        log.info("Current PC: 0x%x", pc)
    end

    -- 读取所有寄存器
    local regs = c_list_regs()
    for _, name in ipairs(regs) do
        local value, size, rc = c_get_reg(name)
        if rc == 0 and type(value) == "number" then
            log.debug("%s = 0x%x", name, value)
        end
    end

    return 0, 0
end
```

### 示例 3: 读取结构体数据

```lua
local log = require("rules_examples.base.log")

function do_syscall(num, struct_ptr, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    if struct_ptr ~= 0 then
        -- 读取结构体的前 4 个字节（假设是 int）
        local field1 = c_read_guest_u32(struct_ptr)
        local field2 = c_read_guest_u32(struct_ptr + 4)

        log.info("Struct fields: %d, %d", field1, field2)

        -- 或者读取整个结构体
        local struct_data = c_read_guest_bytes(struct_ptr, 16)
        -- struct_data 包含 16 字节的原始数据
    end

    return 0, 0
end
```

## 注意事项

1. **内存访问安全**: 在访问客户机内存之前，确保地址有效
2. **字符串读取**: `c_read_string` 会读取到 null 终止符或达到最大长度
3. **寄存器名称**: 不同架构的寄存器名称不同（x86: "rax", ARM: "x0", etc.）
4. **地址转换**: 只有在 QEMU user mode 中，g2h/h2g 才有意义
5. **错误处理**: 大多数函数返回错误码，应该检查返回值

## 参考资料

- 函数实现位置：`linux-user/main.c` 和 `linux-user/syscall.c`
- 系统调用号定义：`/usr/include/asm/unistd_64.h` (x86_64)
