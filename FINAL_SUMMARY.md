# QEMU User Mode Lua Syscall Hooks - 最终实现总结

## 设计方案（更新版）

### 核心思想

每个系统调用对应一个独立的 Lua 脚本文件（如 `read.lua`, `write.lua`），脚本内部定义统一的 `do_syscall` 函数。QEMU 在执行系统调用时，按需加载对应的脚本并缓存，实现模块化和高性能的系统调用拦截。

## 实现细节

### 1. 修改的文件

#### linux-user/main.c

**关键修改：**

1. **导出全局变量**（第 85, 91 行）：
```c
const char *rules_path = NULL;  // 导出给 syscall.c 使用
lua_State *rules_lua_state = NULL;  // 导出给 syscall.c 使用
```

2. **C 辅助函数**（第 698-723 行）：
```c
static int lua_log_message(lua_State *L);      // c_log()
static int lua_get_timestamp(lua_State *L);    // c_get_timestamp()
static int lua_read_guest_string(lua_State *L); // c_read_string()
```

3. **简化的初始化函数**（第 725-758 行）：
```c
static void rules_init(const char *path) {
    // 只初始化 Lua 环境，不预加载脚本
    // 注册 C 辅助函数
    // 验证目录存在性
}
```

#### linux-user/syscall.c

**关键修改：**

1. **外部变量声明**（第 153-155 行）：
```c
extern lua_State *rules_lua_state;
extern const char *rules_path;
```

2. **系统调用名称映射**（第 14144-14230 行）：
```c
static const char *get_syscall_name(int num) {
    // 映射 TARGET_NR_xxx 到 "xxx" 字符串
}
```

3. **按需加载和执行**（第 14233-14359 行）：
```c
static int execute_lua_syscall_hook(int num, abi_long *ret, ...) {
    // 1. 获取系统调用名
    // 2. 检查缓存表 _loaded_syscalls
    // 3. 如果未缓存，加载 <rules_path>/<name>.lua
    // 4. 执行脚本，获取 do_syscall 函数
    // 5. 缓存函数以供后续使用
    // 6. 调用 do_syscall(num, arg1-arg8)
    // 7. 返回结果
}
```

4. **集成到系统调用流程**（第 14376-14388 行）：
```c
// 在 do_syscall() 中调用 Lua 钩子
int lua_hook_result = execute_lua_syscall_hook(...);
if (lua_hook_result == 1) {
    // Lua 已处理，直接返回
}
// 否则继续执行原系统调用
```

### 2. 工作流程

```
用户程序调用系统调用（如 getpid）
    ↓
do_syscall(num=39, ...)
    ↓
execute_lua_syscall_hook(39, ...)
    ↓
get_syscall_name(39) → "getpid"
    ↓
检查缓存表 _loaded_syscalls["getpid"]
    ↓
    ├─→ 已缓存 → 使用缓存的函数
    │
    └─→ 未缓存 → 检查文件 <rules_path>/getpid.lua
              ↓
              ├─→ 文件存在 → 加载并执行脚本
              │                    ↓
              │              获取 do_syscall 函数
              │                    ↓
              │              缓存到 _loaded_syscalls["getpid"]
              │                    ↓
              │              调用 do_syscall(39, arg1-arg8)
              │                    ↓
              │              返回 (action, return_value)
              │                    ↓
              │              action=1? → 是 → 返回 return_value，跳过原系统调用
              │                    │
              │                    └─→ 否 → 继续执行原系统调用
              │
              └─→ 文件不存在 → 继续执行原系统调用
```

### 3. 文件结构

```
SFEQemu/
├── linux-user/
│   ├── main.c           # 修改：Lua 初始化、C 辅助函数
│   └── syscall.c        # 修改：按需加载和执行逻辑
├── rules_examples/      # 新增：示例脚本目录
│   ├── README.md
│   ├── write.lua
│   ├── read.lua
│   ├── getpid.lua
│   ├── open.lua
│   ├── socket.lua
│   └── mmap.lua
├── NEW_BUILD_AND_TEST.md  # 新增：编译和测试指南
└── FINAL_SUMMARY.md      # 本文件
```

## Lua 脚本规范

### 文件命名
- 文件名 = 系统调用名 + `.lua`
- 示例：`read.lua`, `write.lua`, `getpid.lua`

### 脚本结构

```lua
-- 可选：初始化代码
local call_count = 0

-- 必需：do_syscall 函数
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    -- 你的处理逻辑
    call_count = call_count + 1

    -- 返回：(action, return_value)
    -- action: 0=继续执行原调用, 1=已处理
    return 0, 0
end

-- 可选：加载时输出
c_log("Loaded xxx.lua")
```

### C 辅助函数

| 函数 | 参数 | 返回值 | 说明 |
|------|------|--------|------|
| `c_log(msg)` | string | 无 | 输出日志 |
| `c_get_timestamp()` | 无 | (秒, 纳秒) | 获取时间戳 |
| `c_read_string(addr)` | number | string | 读取字符串（占位符）|

## 使用示例

### 基本用法

```bash
# 1. 创建规则目录
mkdir my_rules

# 2. 创建规则文件
cat > my_rules/getpid.lua << 'EOF'
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    c_log("getpid() called - returning fake PID")
    return 1, 99999  -- 返回假 PID
end
EOF

# 3. 运行 QEMU
./qemu-x86_64 --rules my_rules /path/to/program
```

### 高级示例

#### 1. 统计系统调用

```lua
-- write.lua
local stats = {count = 0, bytes = 0}

function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    stats.count = stats.count + 1
    stats.bytes = stats.bytes + count

    if stats.count % 100 == 0 then
        c_log(string.format("Write stats: %d calls, %d bytes",
                           stats.count, stats.bytes))
    end

    return 0, 0
end
```

#### 2. 安全沙箱

```lua
-- socket.lua
function do_syscall(num, domain, type, protocol, arg4, arg5, arg6, arg7, arg8)
    c_log("Network access blocked by sandbox")
    return 1, -1  -- 返回 EPERM
end
```

#### 3. 条件拦截

```lua
-- write.lua
function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    -- 只拦截大量 stderr 写入
    if fd == 2 and count > 10240 then
        c_log("Blocked large stderr write")
        return 1, -1
    end

    return 0, 0
end
```

## 支持的系统调用

当前在 `get_syscall_name()` 中映射的系统调用：

**文件操作**：read, write, open, openat, close, stat, fstat, lstat, access

**I/O 多路复用**：poll, lseek, ioctl

**内存管理**：mmap, mprotect, munmap, brk

**进程管理**：execve, exit, fork, clone, getpid

**网络**：socket, connect, accept, bind, listen

### 添加新系统调用

在 `linux-user/syscall.c` 中编辑 `get_syscall_name()`：

```c
#ifdef TARGET_NR_新系统调用
case TARGET_NR_新系统调用: return "新系统调用";
#endif
```

## 性能特性

### 缓存机制

- **首次调用**：加载脚本 → 解析 → 缓存函数 → 执行
- **后续调用**：直接使用缓存函数 → 执行
- **缓存存储**：Lua 全局表 `_loaded_syscalls`

### 性能影响

1. **无脚本**：仅文件存在性检查（`access()` 系统调用）
2. **首次加载**：文件 I/O + Lua 解析（一次性开销）
3. **缓存后**：Lua 函数调用开销（很小）

### 优化建议

- 只为需要监控的系统调用创建脚本
- 避免在 Lua 脚本中进行复杂计算
- 使用局部变量而非全局变量

## 调试技巧

### 1. 验证脚本语法

```bash
lua my_rules/write.lua
```

### 2. 添加详细日志

```lua
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    c_log(string.format("DEBUG: num=%d, args=[%d,%d,%d,%d,%d,%d,%d,%d]",
                       num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8))
    return 0, 0
end
```

### 3. 使用 strace 对比

```bash
./qemu-x86_64 -strace --rules my_rules ./program 2>&1 | tee log.txt
```

### 4. 测试单个系统调用

创建只包含一个脚本的目录，测试特定系统调用。

## 常见问题

### Q: 脚本修改后不生效？
A: 脚本首次加载后会缓存。修改后需要重启 QEMU。

### Q: 如何知道脚本是否被加载？
A: 在脚本末尾添加：`c_log("Loaded xxx.lua")`

### Q: 可以在多个脚本间共享状态吗？
A: 每个脚本有独立的局部作用域，但可以使用 Lua 全局变量或表。

### Q: 脚本错误会导致程序崩溃吗？
A: 不会。错误会被捕获并输出，然后继续执行原系统调用。

### Q: 如何实现参数修改？
A: 当前设计不支持修改参数，只能选择执行或跳过原调用。要实现参数修改需要额外的 C 代码支持。

## 优势与局限

### 优势

✅ **模块化**：每个系统调用独立文件，易于管理
✅ **按需加载**：只加载实际使用的规则
✅ **高性能**：缓存机制减少重复加载开销
✅ **灵活**：Lua 脚本易于编写和修改
✅ **安全**：脚本错误不影响 QEMU 稳定性
✅ **可扩展**：容易添加新的 C 辅助函数

### 局限

⚠️ **参数读取**：不能直接读取指针指向的内存（需要额外实现）
⚠️ **参数修改**：不支持修改系统调用参数
⚠️ **缓存策略**：脚本修改后需要重启
⚠️ **线程安全**：使用全局 Lua 状态，多线程环境需要额外处理

## 未来改进

### 短期改进

1. **实现内存读取**：
   - 完善 `c_read_string()` 函数
   - 添加 `c_read_bytes()` 函数
   - 添加结构体读取支持

2. **更多 C 辅助函数**：
   - 文件系统操作
   - 网络地址解析
   - 进程信息查询

3. **统计和日志**：
   - 内置的统计收集
   - 日志文件输出
   - JSON 格式的调用记录

### 长期改进

1. **参数修改支持**：允许 Lua 修改系统调用参数
2. **热重载**：支持动态重新加载脚本
3. **规则组合**：支持多个规则文件协同工作
4. **性能优化**：JIT 编译、更智能的缓存
5. **图形界面**：可视化的规则编辑和调试工具

## 实际应用场景

### 1. 安全研究

监控恶意软件行为，了解其系统调用模式。

```bash
# 创建完整的监控规则
for syscall in read write open close socket connect; do
    cat > monitor_rules/${syscall}.lua << EOF
function do_syscall(...)
    c_log("${syscall} called with args: " .. table.concat({...}, ", "))
    return 0, 0
end
EOF
done

./qemu-x86_64 --rules monitor_rules /path/to/suspicious_binary
```

### 2. 教学演示

展示系统调用的工作原理。

```bash
# 为学生演示 getpid
cat > demo_rules/getpid.lua << 'EOF'
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    c_log("========================================")
    c_log("System call: getpid (num=39)")
    c_log("This call returns the process ID")
    c_log("We will return: 12345 (fake PID)")
    c_log("========================================")
    return 1, 12345
end
EOF
```

### 3. 调试和测试

模拟特定的系统调用失败场景。

```bash
# 模拟文件打开失败
cat > test_rules/open.lua << 'EOF'
local fail_count = 0
function do_syscall(num, pathname, flags, mode, ...)
    fail_count = fail_count + 1
    if fail_count == 3 then
        c_log("Simulating open failure")
        return 1, -2  -- ENOENT
    end
    return 0, 0
end
EOF
```

## 结论

这个实现为 QEMU 用户模式提供了一个强大、灵活、模块化的系统调用拦截框架。通过 Lua 脚本，用户可以轻松地监控、修改或阻止系统调用，而无需修改 QEMU 源代码。

**开始使用**：
1. 阅读 `NEW_BUILD_AND_TEST.md` 了解编译步骤
2. 查看 `rules_examples/` 目录学习脚本编写
3. 创建自己的规则目录并开始实验

**获取帮助**：
- 查看示例脚本：`rules_examples/`
- 阅读详细文档：`rules_examples/README.md`
- 参考测试指南：`NEW_BUILD_AND_TEST.md`

---

**项目信息**
- 修改日期：2025-11-05
- QEMU 版本：基于当前 master 分支
- Lua 版本：5.3+
- 许可：GPL v2（遵循 QEMU 许可）
