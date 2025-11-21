# QEMU Lua Syscall Hooks - 编译和测试指南（更新版）

## 新的设计

### 关键变化

1. **脚本命名**: Lua 脚本文件名直接使用系统调用名，如 `read.lua`, `write.lua`
2. **函数命名**: 脚本内部定义 `do_syscall` 函数（不再是 `syscall_<name>`）
3. **按需加载**: 脚本在第一次调用相应系统调用时才加载，之后缓存
4. **模块化**: 每个系统调用一个独立文件，更易于管理

## 编译步骤

### 1. 安装依赖

```bash
# Ubuntu/Debian
sudo apt-get install lua5.3 liblua5.3-dev

# CentOS/RHEL
sudo yum install lua lua-devel

# macOS
brew install lua
```

### 2. 编译 QEMU

```bash
cd /media/user/ddisk/Work/SFEQemu

mkdir -p build && cd build

# 配置
../configure --target-list=x86_64-linux-user \
             --enable-debug \
             --disable-werror

# 编译
make -j$(nproc)
```

### 3. 验证

```bash
./qemu-x86_64 --help | grep rules
```

应输出：
```
-rules path      set the rules folder path
```

## 快速测试

### 1. 创建测试程序

```c
// test_program.c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    pid_t pid;

    printf("Starting test program...\n");

    // Test getpid (will be intercepted)
    pid = getpid();
    printf("My PID is: %d\n", pid);

    // Test write (will be logged)
    write(1, "Hello from write!\n", 18);

    // Test multiple getpid calls
    for (int i = 0; i < 3; i++) {
        pid = getpid();
        printf("PID call %d: %d\n", i + 1, pid);
    }

    return 0;
}
```

编译：
```bash
gcc -o test_program test_program.c
```

### 2. 创建测试规则

```bash
mkdir test_rules
```

创建 `test_rules/getpid.lua`:
```lua
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    c_log("getpid() intercepted - returning fake PID 99999")
    return 1, 99999
end

c_log("Loaded getpid.lua")
```

创建 `test_rules/write.lua`:
```lua
function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    c_log(string.format("write(fd=%d, count=%d)", fd, count))
    return 0, 0
end

c_log("Loaded write.lua")
```

### 3. 运行测试

```bash
./qemu-x86_64 --rules test_rules ./test_program
```

期望输出：
```
Rules folder path: test_rules
Lua environment initialized. Scripts will be loaded on demand.
Starting test program...
[Lua Log] Loaded getpid.lua
[Lua Log] getpid() intercepted - returning fake PID 99999
My PID is: 99999
[Lua Log] Loaded write.lua
[Lua Log] write(fd=1, count=18)
Hello from write!
[Lua Log] getpid() intercepted - returning fake PID 99999
PID call 1: 99999
[Lua Log] getpid() intercepted - returning fake PID 99999
PID call 2: 99999
[Lua Log] getpid() intercepted - returning fake PID 99999
PID call 3: 99999
```

注意：
- `getpid.lua` 在第一次调用 `getpid()` 时加载
- `write.lua` 在第一次调用 `write()` 时加载
- 后续调用使用缓存的函数

## 使用示例规则

项目提供了示例规则在 `rules_examples/` 目录：

```bash
# 使用所有示例规则
./qemu-x86_64 --rules rules_examples ./test_program

# 只使用部分规则
mkdir my_rules
cp rules_examples/getpid.lua my_rules/
cp rules_examples/write.lua my_rules/
./qemu-x86_64 --rules my_rules ./test_program
```

## 创建自定义规则

### 示例 1: 监控文件操作

创建 `my_rules/open.lua`:
```lua
function do_syscall(num, pathname, flags, mode, arg4, arg5, arg6, arg7, arg8)
    c_log(string.format("Opening file: flags=0x%x, mode=0x%x", flags, mode))
    return 0, 0
end
```

### 示例 2: 阻止网络连接

创建 `my_rules/socket.lua`:
```lua
function do_syscall(num, domain, type, protocol, arg4, arg5, arg6, arg7, arg8)
    c_log("Socket creation blocked!")
    return 1, -1  -- Return error
end
```

### 示例 3: 统计系统调用

创建 `my_rules/read.lua`:
```lua
local count = 0
local total_bytes = 0

function do_syscall(num, fd, buf, size, arg4, arg5, arg6, arg7, arg8)
    count = count + 1
    total_bytes = total_bytes + size

    if count % 10 == 0 then
        c_log(string.format("Read stats: %d calls, %d bytes", count, total_bytes))
    end

    return 0, 0
end
```

## 调试

### 检查脚本语法

```bash
lua my_rules/write.lua
```

### 使用 strace 对比

```bash
# 查看实际的系统调用和 Lua 拦截
./qemu-x86_64 -strace --rules my_rules ./test_program 2>&1 | tee output.log
```

### 添加调试输出

在脚本中添加详细日志：
```lua
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    c_log(string.format("DEBUG: num=%d, arg1=%d, arg2=%d, arg3=%d",
                       num, arg1, arg2, arg3))
    return 0, 0
end
```

## 性能测试

### 测试脚本加载开销

创建 `perf_test.c`:
```c
#include <unistd.h>
#include <stdio.h>
#include <time.h>

#define ITERATIONS 100000

int main() {
    clock_t start, end;
    double time_used;

    start = clock();
    for (int i = 0; i < ITERATIONS; i++) {
        getpid();
    }
    end = clock();

    time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Time: %.6f seconds\n", time_used);
    printf("Avg per call: %.3f microseconds\n",
           (time_used * 1000000) / ITERATIONS);

    return 0;
}
```

比较：
```bash
# 无 Lua 规则
./qemu-x86_64 ./perf_test

# 有 Lua 规则但不拦截
mkdir empty_rules
./qemu-x86_64 --rules empty_rules ./perf_test

# 有 Lua 规则且拦截（只日志）
mkdir log_rules
echo 'function do_syscall(...) return 0, 0 end' > log_rules/getpid.lua
./qemu-x86_64 --rules log_rules ./perf_test

# 有 Lua 规则且拦截（返回假值）
cp rules_examples/getpid.lua log_rules/
./qemu-x86_64 --rules log_rules ./perf_test
```

## 常见问题

### Q: 脚本没有被加载？

检查：
1. 文件名是否正确（系统调用名 + .lua）
2. 文件是否在指定的 rules 目录下
3. 系统调用是否被执行
4. 系统调用名是否在 `get_syscall_name()` 中映射

查看支持的系统调用：
```bash
grep "case TARGET_NR_" linux-user/syscall.c | grep "return" | head -20
```

### Q: do_syscall 函数没有被调用？

确保：
1. 函数名是 `do_syscall`（不是其他名字）
2. 脚本没有语法错误
3. 脚本已被加载（查看初始化日志）

### Q: 如何添加新系统调用？

编辑 `linux-user/syscall.c` 中的 `get_syscall_name()`:
```c
#ifdef TARGET_NR_your_syscall
case TARGET_NR_your_syscall: return "your_syscall";
#endif
```

然后重新编译 QEMU。

### Q: 脚本修改后需要重启 QEMU 吗？

是的。脚本在第一次调用时加载并缓存，修改后需要重启 QEMU。

## 高级用例

### 安全沙箱

创建多个规则文件限制程序行为：

```bash
mkdir sandbox_rules

# 阻止所有网络操作
cat > sandbox_rules/socket.lua << 'EOF'
function do_syscall(...)
    c_log("Network access blocked")
    return 1, -1
end
EOF

cat > sandbox_rules/connect.lua << 'EOF'
function do_syscall(...)
    c_log("Connect blocked")
    return 1, -1
end
EOF

# 监控文件操作
cat > sandbox_rules/open.lua << 'EOF'
function do_syscall(num, pathname, flags, mode, ...)
    c_log(string.format("File access: 0x%x", pathname))
    return 0, 0
end
EOF
```

运行：
```bash
./qemu-x86_64 --rules sandbox_rules ./untrusted_program
```

### 行为分析

创建规则记录所有系统调用：

```bash
mkdir trace_rules

for syscall in read write open close socket connect; do
    cat > trace_rules/${syscall}.lua << EOF
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    local sec, nsec = c_get_timestamp()
    c_log(string.format("[%d.%09d] ${syscall}: %d, %d, %d",
                       sec, nsec, arg1, arg2, arg3))
    return 0, 0
end
EOF
done
```

## 总结

新的设计具有以下优势：

1. **模块化**: 每个系统调用一个文件，易于管理
2. **按需加载**: 只加载实际使用的规则，减少启动时间
3. **缓存机制**: 加载后缓存，后续调用性能好
4. **简洁**: 统一的 `do_syscall` 函数名，易于理解

开始使用：
1. 创建规则目录
2. 为需要拦截的系统调用创建 `.lua` 文件
3. 定义 `do_syscall` 函数
4. 使用 `--rules` 参数运行 QEMU
