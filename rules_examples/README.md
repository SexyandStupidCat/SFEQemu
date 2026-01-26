# QEMU Lua Syscall Rules - 示例脚本

## 概述

此目录包含 QEMU 用户模式 Lua 系统调用拦截的示例脚本。规则目录以 `--rules <dir>` 指定，推荐结构如下：

```
config/      # 配置（config/env 会被 entry.lua 自动加载）
base/        # 通用基础模块（log、sftrace 等）
data/        # 数据（预留）
plugins/     # 插件目录
  fakefile/  # fakefile 插件（含自身 config/data/default）
syscall/     # 系统调用 hook（按 syscall 名命名，如 open.lua）
entry.lua    # syscall 入口（每次 syscall 先进入这里）
finish.lua   # syscall 结束（每次 syscall 结束进入这里）
```

## 文件命名规范

- 文件名必须是系统调用名称，如：`read.lua`, `write.lua`, `open.lua`
- QEMU 会根据系统调用名自动查找对应的 `.lua` 文件

## 脚本格式

每个 `syscall/<name>.lua` 脚本必须定义一个 `do_syscall` 函数：

```lua
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    -- 你的处理逻辑

    -- 返回值：
    -- action: 0 = 继续执行原系统调用, 1 = 已处理，使用返回值
    -- return_value: 系统调用的返回值
    return action, return_value
end
```

### 参数说明

- `num`: 系统调用号
- `arg1` - `arg8`: 系统调用的参数（具体含义取决于系统调用）

### 返回值

函数必须返回两个值：

1. **action** (整数):
   - `0`: 继续执行原始系统调用
   - `1`: 跳过原始系统调用，使用提供的返回值

2. **return_value** (整数):
   - 当 action = 1 时，这个值将作为系统调用的返回值

## 可用的 C 辅助函数

### c_log(message)
输出日志消息

```lua
c_log("This is a log message")
```

### c_get_timestamp()
获取当前时间戳，返回 (秒, 纳秒)

```lua
local sec, nsec = c_get_timestamp()
c_log(string.format("Timestamp: %d.%09d", sec, nsec))
```

### c_read_string(addr)
读取字符串（当前为占位符实现）

```lua
local str = c_read_string(pathname)
```

## 示例文件

### write.lua
监控 write 系统调用，记录大量写入，可选择性阻止过大的 stderr 写入。

### read.lua
监控 read 系统调用，特别关注从 stdin 的读取。

### getpid.lua
拦截 getpid 调用并返回假的 PID (99999)。

### open.lua
监控文件打开操作，可以基于路径名进行过滤（需要实现字符串读取）。

### socket.lua
监控 socket 创建，阻止创建原始套接字。

### mmap.lua
监控内存映射操作，记录大型映射和匿名映射。

## 使用方法

1. **创建规则目录**（建议直接复制本目录结构）：
   ```bash
   cp -r rules_examples my_rules
   ```

3. **运行 QEMU**：
   ```bash
   ./qemu-x86_64 --rules my_rules /path/to/binary
   ```

4. **观察输出**：
   - 每次系统调用会先进入 `entry.lua`，由它在 `syscall/` 目录中按名称分发并执行 hook
   - 系统调用完成后会进入 `finish.lua`（可记录返回值/执行结果）

## 示例场景

### 场景 1: 监控文件操作

创建 `my_rules/open.lua`, `my_rules/read.lua`, `my_rules/write.lua`

```bash
./qemu-x86_64 --rules my_rules ./my_program
```

### 场景 2: 返回假的系统信息

创建 `my_rules/getpid.lua`

```lua
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    return 1, 12345  -- 返回假 PID
end
```

### 场景 3: 安全沙箱

创建多个规则文件来限制程序行为：

**socket.lua** - 阻止所有网络连接：
```lua
function do_syscall(num, domain, type, protocol, arg4, arg5, arg6, arg7, arg8)
    c_log("Blocked socket creation")
    return 1, -1  -- 返回错误
end
```

**open.lua** - 限制文件访问（需要实现路径读取）：
```lua
function do_syscall(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    -- 假设有 c_read_string 实现
    -- local path = c_read_string(pathname)
    -- if not path:match("^/tmp/") then
    --     c_log("Blocked access to: " .. path)
    --     return 1, -13  -- -EACCES
    -- end
    return 0, 0
end
```

## 调试技巧

### 1. 添加详细日志

```lua
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    c_log(string.format("Called with: num=%d, arg1=%d, arg2=%d", num, arg1, arg2))
    return 0, 0
end
```

### 2. 检查脚本语法

```bash
lua my_rules/write.lua
```

### 3. 测试单个系统调用

只创建一个规则文件，测试特定系统调用的拦截。

## 性能考虑

- **首次加载**: 第一次调用某个系统调用时会加载对应的 `.lua` 文件
- **缓存**: 加载后的函数会被缓存，后续调用直接使用
- **开销**: 每次系统调用都会检查是否有对应的 Lua 文件，但未加载的脚本只有文件存在性检查的开销

## 扩展功能

### 状态跟踪

你可以在脚本中使用全局变量来跟踪状态：

```lua
-- write.lua
local write_count = 0
local total_bytes = 0

function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    write_count = write_count + 1
    total_bytes = total_bytes + count

    if write_count % 100 == 0 then
        c_log(string.format("Stats: %d writes, %d bytes total", write_count, total_bytes))
    end

    return 0, 0
end
```

### 条件拦截

根据参数值决定是否拦截：

```lua
function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    -- 只拦截写入到特定 fd 的操作
    if fd == 3 then
        c_log("Intercepted write to fd 3")
        return 1, count  -- 假装成功但不实际写入
    end
    return 0, 0
end
```

## 注意事项

1. 函数名必须是 `do_syscall`，不能是其他名字
2. 文件名必须与系统调用名完全匹配
3. 每个文件只能包含一个系统调用的处理逻辑
4. 脚本错误不会导致 QEMU 崩溃，而是输出错误并继续执行原系统调用
5. 多个脚本之间是独立的，不共享全局变量（除非使用 Lua 的模块机制）

## 常见问题

### Q: 如何知道某个系统调用的参数含义？
A: 使用 `man 2 <syscall_name>` 查看系统调用手册。

### Q: 为什么我的脚本没有被加载？
A: 检查：
- 文件名是否与系统调用名完全匹配
- 文件是否有 `.lua` 扩展名
- 系统调用名是否在 `get_syscall_name()` 中有映射

### Q: 如何添加对新系统调用的支持？
A: 在 `linux-user/syscall.c` 的 `get_syscall_name()` 函数中添加对应的 case 分支。

### Q: 脚本中的错误会导致程序崩溃吗？
A: 不会。脚本错误会被捕获并输出，然后继续执行原系统调用。

## 参考资源

- Linux 系统调用: `man 2 syscalls`
- Lua 手册: https://www.lua.org/manual/5.3/
- QEMU 文档: https://www.qemu.org/docs/master/
