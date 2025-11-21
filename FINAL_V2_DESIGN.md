# QEMU Lua Syscall Hooks - 最终设计（V2）

## 设计理念

**核心思想**：Lua 脚本完全控制系统调用的执行流程。

- 如果存在 `<syscall_name>.lua`，就执行 Lua 脚本
- Lua 脚本可以调用 `c_do_syscall()` 来执行原始系统调用
- Lua 脚本可以选择不调用原始系统调用
- Lua 脚本可以在系统调用前后做任何处理

## 实现细节

### 修改的文件

#### 1. linux-user/syscall.c

**添加的全局变量**（第 158 行）：
```c
static __thread CPUArchState *current_cpu_env = NULL;
```
用于保存当前 CPU 环境，供 Lua 回调使用。

**前向声明**（第 160-164 行）：
```c
abi_long do_syscall1(CPUArchState *cpu_env, int num, abi_long arg1,
                     abi_long arg2, abi_long arg3, abi_long arg4,
                     abi_long arg5, abi_long arg6, abi_long arg7,
                     abi_long arg8);
```

**Lua C 函数** - `lua_do_original_syscall`（第 14154-14184 行）：
```c
static int lua_do_original_syscall(lua_State *L)
{
    // 从 Lua 栈获取参数
    // 调用 do_syscall1 执行原始系统调用
    // 返回结果到 Lua
}
```

**初始化函数** - `init_lua_syscall_functions`（第 14190-14195 行）：
```c
void init_lua_syscall_functions(lua_State *L)
{
    if (L) {
        lua_register(L, "c_do_syscall", lua_do_original_syscall);
    }
}
```

**系统调用钩子** - `execute_lua_syscall_hook`（第 14297-14386 行）：
```c
static int execute_lua_syscall_hook(CPUArchState *cpu_env, int num, abi_long *ret, ...)
{
    // 1. 检查是否存在 <rules_path>/<syscall_name>.lua
    // 2. 如果不存在，返回 0（执行原始系统调用）
    // 3. 保存 current_cpu_env
    // 4. 加载并执行 Lua 脚本
    // 5. 获取脚本中的 do_syscall 函数
    // 6. 调用 do_syscall(num, arg1-arg8)
    // 7. 获取返回值
    // 8. 清除 current_cpu_env
    // 9. 返回 1（已由 Lua 处理）
}
```

**修改 do_syscall1**（第 9461 行）：
```c
// 将 static 去掉，使其可以被其他函数调用
abi_long do_syscall1(CPUArchState *cpu_env, int num, ...)
```

**集成到 do_syscall**（第 14456-14467 行）：
```c
int lua_hook_result = execute_lua_syscall_hook(cpu_env, num, &ret,
                                                 arg1, arg2, arg3, arg4,
                                                 arg5, arg6, arg7, arg8);

if (lua_hook_result == 1) {
    /* Syscall was handled by Lua script */
    // 记录并返回
    return ret;
}

/* No Lua script found, execute normal syscall */
ret = do_syscall1(cpu_env, num, arg1, arg2, arg3, arg4,
                  arg5, arg6, arg7, arg8);
```

#### 2. linux-user/main.c

**添加外部函数声明**（第 93-94 行）：
```c
void init_lua_syscall_functions(lua_State *L);
```

**调用初始化函数**（第 760-761 行）：
```c
/* Register syscall functions from syscall.c */
init_lua_syscall_functions(rules_lua_state);
```

### 工作流程

```
用户程序调用 write(fd, buf, count)
    ↓
do_syscall(num=1, fd, buf, count, ...)
    ↓
execute_lua_syscall_hook(cpu_env, 1, &ret, fd, buf, count, ...)
    ↓
检查文件 <rules_path>/write.lua 是否存在
    ↓
    ├─→ 文件不存在
    │       ↓
    │   返回 0
    │       ↓
    │   执行 do_syscall1(...)  [原始系统调用]
    │
    └─→ 文件存在
            ↓
        保存 current_cpu_env = cpu_env
            ↓
        加载 write.lua
            ↓
        执行脚本（定义函数和顶层代码）
            ↓
        获取 do_syscall 函数
            ↓
        调用 do_syscall(1, fd, buf, count, ...)
            ↓
        【Lua 脚本内部】
            ↓
        c_log("Writing...")  [前处理]
            ↓
        ret = c_do_syscall(1, fd, buf, count, ...)
            ↓
            └─→ 调用 lua_do_original_syscall
                    ↓
                调用 do_syscall1(current_cpu_env, 1, fd, buf, count, ...)
                    ↓
                【执行真正的 write 系统调用】
                    ↓
                返回结果到 Lua
            ↓
        c_log("Wrote...")  [后处理]
            ↓
        return ret
            ↓
        【返回到 C 代码】
            ↓
        获取 Lua 返回值
            ↓
        清除 current_cpu_env = NULL
            ↓
        返回 1 (已处理)
            ↓
        记录并返回结果
```

## Lua 脚本格式

### 基本结构

```lua
-- 可选：初始化代码
local state = {}

-- 必需：do_syscall 函数
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    -- 你的逻辑

    -- 可以调用原始系统调用
    local ret = c_do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)

    -- 返回值
    return ret
end

-- 可选：加载时的代码
c_log("Loaded xxx.lua")
```

### 可用的 C 函数

1. **c_do_syscall(num, arg1-arg8)**
   - 调用原始系统调用
   - 返回系统调用的返回值

2. **c_log(message)**
   - 输出日志消息

3. **c_get_timestamp()**
   - 获取时间戳
   - 返回 (秒, 纳秒)

4. **c_read_string(addr)**
   - 读取字符串（占位符实现）

## 使用示例

### 示例 1: 监控（前后处理）

```lua
-- write.lua
function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    c_log(string.format("Writing %d bytes to fd %d", count, fd))

    local ret = c_do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)

    c_log(string.format("Wrote %d bytes, ret=%d", count, ret))

    return ret
end
```

### 示例 2: 修改返回值

```lua
-- getpid.lua
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    local real_pid = c_do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    c_log(string.format("Real PID: %d, returning: %d", real_pid, real_pid + 10000))
    return real_pid + 10000
end
```

### 示例 3: 完全拦截（不调用原始）

```lua
-- socket.lua
function do_syscall(num, domain, type, protocol, arg4, arg5, arg6, arg7, arg8)
    if domain == 2 then  -- AF_INET
        c_log("Blocked network socket")
        return -1  -- 不调用原始，直接返回错误
    end

    return c_do_syscall(num, domain, type, protocol, arg4, arg5, arg6, arg7, arg8)
end
```

### 示例 4: 统计收集

```lua
-- read.lua
local total_bytes = 0

function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    local ret = c_do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)

    if ret > 0 then
        total_bytes = total_bytes + ret
        c_log(string.format("Total read: %d bytes", total_bytes))
    end

    return ret
end
```

## 文件组织

```
SFEQemu/
├── linux-user/
│   ├── main.c               # 初始化 Lua，注册 C 函数
│   └── syscall.c            # 系统调用拦截逻辑
│
├── rules_examples_v2/       # V2 示例（使用 c_do_syscall）
│   ├── README.md            # 完整文档
│   ├── write.lua            # 前后处理示例
│   ├── getpid.lua           # 修改返回值示例
│   ├── open.lua             # 条件转发示例
│   ├── read.lua             # 统计收集示例
│   └── socket.lua           # 完全拦截示例
│
└── FINAL_V2_DESIGN.md       # 本文件
```

## 关键特性

### 1. 完全控制

Lua 脚本可以：
- ✅ 在系统调用前做任何处理
- ✅ 调用或不调用原始系统调用
- ✅ 修改返回值
- ✅ 在系统调用后做任何处理

### 2. 透明性

对于没有 Lua 脚本的系统调用，完全透明：
- 没有性能影响
- 正常执行原始系统调用
- 无需修改应用程序

### 3. 灵活性

- 可以创建任意复杂的拦截逻辑
- 支持状态保持
- 支持条件判断
- 支持统计收集

### 4. 安全性

- Lua 错误不会导致 QEMU 崩溃
- 脚本错误时自动执行原始系统调用
- 使用线程局部存储支持多线程

## 性能考虑

### 性能影响

1. **无脚本时**：
   - 一次文件存在性检查（`access()`）
   - 非常小的开销

2. **有脚本时**：
   - 每次都重新加载脚本（无缓存）
   - 适合开发和调试
   - 如需优化，可以添加缓存机制

### 优化建议

1. 只为需要监控的系统调用创建脚本
2. 保持 Lua 逻辑简单
3. 避免频繁的日志输出
4. 使用局部变量而非全局变量

## 与之前版本的区别

| 特性 | 旧版本 | 新版本 (V2) |
|------|--------|------------|
| 返回值 | (action, return_value) | return_value |
| 调用原始 | action=0 | c_do_syscall() |
| 脚本缓存 | 有 | 无 |
| 灵活性 | 有限 | 完全控制 |
| 代码行数 | 更多 | 更少 |
| 易用性 | 中等 | 高 |

## 测试

### 快速测试

```bash
# 1. 编译 QEMU
cd build && make

# 2. 创建测试程序
cat > test.c << 'EOF'
#include <stdio.h>
#include <unistd.h>

int main() {
    printf("PID: %d\n", getpid());
    write(1, "Hello\n", 6);
    return 0;
}
EOF
gcc -o test test.c

# 3. 创建规则
mkdir test_rules
cat > test_rules/getpid.lua << 'EOF'
function do_syscall(num, ...)
    local real_pid = c_do_syscall(num, ...)
    c_log(string.format("Real PID: %d, returning: 99999", real_pid))
    return 99999
end
EOF

cat > test_rules/write.lua << 'EOF'
function do_syscall(num, fd, buf, count, ...)
    c_log(string.format("Before write: fd=%d, count=%d", fd, count))
    local ret = c_do_syscall(num, fd, buf, count, ...)
    c_log(string.format("After write: ret=%d", ret))
    return ret
end
EOF

# 4. 运行测试
./qemu-x86_64 --rules test_rules ./test
```

期望输出：
```
Rules folder path: test_rules
Lua environment initialized. Scripts will be loaded on demand.
[Lua Log] Real PID: 12345, returning: 99999
PID: 99999
[Lua Log] Before write: fd=1, count=6
[Lua Log] After write: ret=6
Hello
```

## 应用场景

1. **安全研究**：监控恶意软件行为
2. **调试**：追踪系统调用
3. **测试**：模拟错误条件
4. **性能分析**：测量调用时间
5. **沙箱**：限制程序行为
6. **审计**：记录所有操作

## 未来改进

1. **缓存机制**：缓存已加载的脚本提高性能
2. **更多 C 函数**：内存读写、文件操作等
3. **参数修改**：允许 Lua 修改系统调用参数
4. **热重载**：无需重启 QEMU 即可更新脚本
5. **配置文件**：全局配置和规则优先级

## 总结

这个设计提供了：
- ✅ **完全控制**：Lua 可以决定是否调用原始系统调用
- ✅ **简单易用**：只需定义 `do_syscall` 函数
- ✅ **高度灵活**：支持任意复杂的拦截逻辑
- ✅ **安全可靠**：错误不会影响 QEMU 稳定性
- ✅ **即时生效**：脚本修改立即生效

**开始使用：**
1. 查看 `rules_examples_v2/README.md` 了解详细用法
2. 复制示例脚本到自己的规则目录
3. 运行 `./qemu-x86_64 --rules <your_rules> <program>`

---

**文档版本**: V2
**更新日期**: 2025-11-05
**状态**: 已完成并测试
