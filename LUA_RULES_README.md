# QEMU User Mode Lua Syscall Rules

## 概述

此修改为 QEMU 用户模式添加了 Lua 脚本支持，允许在系统调用执行前进行拦截和修改。

## 修改的文件

1. **linux-user/main.c**
   - 添加了 Lua 头文件引用
   - 添加了 `rules_lua_state` 全局变量
   - 添加了 `--rules` 命令行参数
   - 实现了 `rules_init()` 函数来加载 Lua 脚本

2. **linux-user/syscall.c**
   - 添加了 Lua 头文件引用
   - 声明了外部变量 `rules_lua_state`
   - 实现了 `get_syscall_name()` 函数：从系统调用号获取名称
   - 实现了 `execute_lua_syscall_hook()` 函数：执行 Lua 拦截逻辑
   - 修改了 `do_syscall()` 函数：在执行系统调用前检查 Lua 钩子

## 使用方法

### 1. 编译 QEMU

确保在编译 QEMU 时链接了 Lua 库。你可能需要在 `meson.build` 中添加 Lua 依赖。

### 2. 创建 Lua 规则脚本

创建一个包含 Lua 脚本的目录，例如 `rules/`：

```bash
mkdir rules
```

在该目录下创建 Lua 脚本文件（例如 `hook.lua`）：

```lua
-- 拦截 write 系统调用
function syscall_write(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    print(string.format("[Lua] write(fd=%d, count=%d)", fd, count))
    return 0, 0  -- 返回 0 表示继续正常执行
end

-- 拦截 getpid 并返回假的 PID
function syscall_getpid(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    print("[Lua] getpid() intercepted")
    return 1, 12345  -- 返回 1 表示已处理，返回值为 12345
end
```

### 3. 运行 QEMU

使用 `--rules` 参数指定 Lua 脚本目录：

```bash
./qemu-x86_64 --rules /path/to/rules /path/to/binary
```

## Lua 脚本编写规范

### 函数命名

Lua 函数必须遵循以下命名格式：

```lua
function syscall_<syscall_name>(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
```

其中 `<syscall_name>` 是系统调用的名称（如 `read`、`write`、`open` 等）。

### 函数参数

- `num`: 系统调用号
- `arg1` - `arg8`: 系统调用的参数（最多 8 个）

### 返回值

函数必须返回两个值：

1. **action** (整数):
   - `0`: 继续执行原始系统调用
   - `1`: 跳过原始系统调用，使用提供的返回值

2. **return_value** (整数):
   - 当 action = 1 时，这个值将作为系统调用的返回值

### 示例

```lua
-- 示例 1: 记录所有 open 调用但继续执行
function syscall_open(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    print(string.format("Opening file: pathname=0x%x", pathname))
    return 0, 0  -- 继续执行
end

-- 示例 2: 阻止某些文件的打开（返回错误）
function syscall_open(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    -- 假设我们检查了路径并决定拒绝
    print("Access denied!")
    return 1, -13  -- 返回 -EACCES (Permission denied)
end

-- 示例 3: 修改系统调用行为
function syscall_getpid(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    return 1, 9999  -- 返回假的 PID
end
```

## 支持的系统调用

目前在 `get_syscall_name()` 函数中映射了以下常见系统调用：

- read, write, open, openat, close
- stat, fstat, lstat
- poll, lseek
- mmap, mprotect, munmap, brk
- ioctl, access
- execve, exit, fork, clone
- getpid
- socket, connect, accept, bind, listen

如需支持更多系统调用，可以在 `linux-user/syscall.c` 的 `get_syscall_name()` 函数中添加相应的 case 分支。

## 注意事项

1. **性能影响**: 每个系统调用都会检查是否存在 Lua 钩子，这会带来轻微的性能开销。

2. **线程安全**: 当前实现使用全局的 Lua 状态，在多线程环境下可能需要额外的同步机制。

3. **内存访问**: Lua 脚本接收的是指针地址（数值），如果需要读取指针指向的内容，需要在 C 代码中实现相应的辅助函数并注册到 Lua 环境。

4. **错误处理**: 如果 Lua 脚本执行出错，系统会打印错误信息但继续执行原始系统调用。

## 扩展功能

你可以在 Lua 环境中注册 C 函数，以提供更强大的功能，例如：

- 读取内存内容
- 修改系统调用参数
- 访问文件系统
- 网络过滤
- 等等

在 `linux-user/main.c` 的 `rules_init()` 函数中添加：

```c
// 注册 C 函数到 Lua
lua_register(rules_lua_state, "c_function_name", c_function);
```

## 示例用例

1. **安全沙箱**: 限制程序只能访问特定目录的文件
2. **系统调用追踪**: 详细记录程序的系统调用行为
3. **行为分析**: 检测和分析恶意软件行为
4. **测试和调试**: 模拟特定的系统环境或错误条件
5. **性能分析**: 统计系统调用频率和参数

## 调试

启用 strace 日志可以同时看到 Lua 拦截和实际的系统调用：

```bash
./qemu-x86_64 -strace --rules /path/to/rules /path/to/binary
```
