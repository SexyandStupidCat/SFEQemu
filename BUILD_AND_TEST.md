# QEMU Lua Syscall Hooks - 编译和测试指南

## 修改总结

### 1. 修改的文件

#### linux-user/main.c
- 添加了 Lua 头文件 (`lua.h`, `lualib.h`, `lauxlib.h`)
- 添加了全局变量 `rules_lua_state`
- 添加了命令行参数 `--rules` 用于指定 Lua 脚本目录
- 实现了 `rules_init()` 函数来加载目录中的所有 `.lua` 文件
- 添加了 C 辅助函数供 Lua 调用：
  - `c_log()` - 从 Lua 打印日志
  - `c_get_timestamp()` - 获取当前时间戳
  - `c_read_string()` - 读取字符串（占位符实现）

#### linux-user/syscall.c
- 添加了 Lua 头文件
- 声明了外部变量 `rules_lua_state`
- 实现了 `get_syscall_name()` - 将系统调用号映射到名称
- 实现了 `execute_lua_syscall_hook()` - 执行 Lua 钩子函数
- 修改了 `do_syscall()` - 在执行系统调用前检查并执行 Lua 钩子

## 编译步骤

### 1. 确保 Lua 开发库已安装

在 Ubuntu/Debian 上：
```bash
sudo apt-get install lua5.3 liblua5.3-dev
```

在 CentOS/RHEL 上：
```bash
sudo yum install lua lua-devel
```

在 macOS 上：
```bash
brew install lua
```

### 2. 配置 QEMU 构建

你需要确保 meson 构建系统能找到 Lua 库。检查 `meson.build` 和 `meson_options.txt` 文件。

如果需要，手动添加 Lua 依赖到 `linux-user/meson.build`：

```meson
lua_dep = dependency('lua5.3', required: false)
if not lua_dep.found()
  lua_dep = dependency('lua', required: false)
endif

if lua_dep.found()
  qemu_user_sources += files('main.c', 'syscall.c')
  qemu_user_deps += lua_dep
endif
```

### 3. 配置和编译 QEMU

```bash
cd /media/user/ddisk/Work/SFEQemu

# 创建构建目录
mkdir -p build
cd build

# 配置（确保启用 user-mode）
../configure --target-list=x86_64-linux-user \
             --enable-debug \
             --disable-werror

# 或者使用 meson（如果项目使用 meson）
meson setup . .. --prefix=/usr/local

# 编译
make -j$(nproc)

# 或者
ninja
```

### 4. 验证编译

```bash
./qemu-x86_64 --help | grep rules
```

应该看到类似输出：
```
-rules path      set the rules folder path
```

## 测试

### 1. 创建测试程序

创建一个简单的测试程序 `test_program.c`：

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    pid_t pid;

    printf("Starting test program...\n");

    // Test getpid
    pid = getpid();
    printf("My PID is: %d\n", pid);

    // Test write
    write(1, "Hello from write syscall!\n", 26);

    // Test multiple getpid calls
    for (int i = 0; i < 3; i++) {
        pid = getpid();
        printf("PID call %d: %d\n", i + 1, pid);
    }

    return 0;
}
```

编译测试程序：
```bash
gcc -o test_program test_program.c
```

### 2. 创建简单的 Lua 规则

创建目录和规则文件：
```bash
mkdir -p lua_rules
cat > lua_rules/test_rules.lua << 'EOF'
-- Simple test rules

function syscall_write(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    print(string.format("[Lua] write called: fd=%d, count=%d", fd, count))
    return 0, 0
end

function syscall_getpid(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    print("[Lua] getpid intercepted - returning fake PID 99999")
    return 1, 99999
end

print("Test Lua rules loaded!")
EOF
```

### 3. 运行测试

```bash
./qemu-x86_64 --rules lua_rules ./test_program
```

期望输出：
```
Rules folder path: lua_rules
Loading Lua rule: lua_rules/test_rules.lua
Test Lua rules loaded!
Successfully loaded 1 Lua rule(s)
Starting test program...
[Lua] getpid intercepted - returning fake PID 99999
My PID is: 99999
[Lua] write called: fd=1, count=26
Hello from write syscall!
[Lua] getpid intercepted - returning fake PID 99999
PID call 1: 99999
[Lua] getpid intercepted - returning fake PID 99999
PID call 2: 99999
[Lua] getpid intercepted - returning fake PID 99999
PID call 3: 99999
```

### 4. 测试高级功能

使用提供的 `advanced_rules_example.lua`：

```bash
cp advanced_rules_example.lua lua_rules/
./qemu-x86_64 --rules lua_rules ./test_program
```

### 5. 测试 strace 集成

```bash
./qemu-x86_64 -strace --rules lua_rules ./test_program 2>&1 | head -20
```

这将同时显示 strace 输出和 Lua 拦截信息。

## 调试

### 编译问题

1. **找不到 Lua 头文件**：
   ```bash
   # 查找 Lua 头文件位置
   find /usr -name "lua.h" 2>/dev/null

   # 如果需要，设置 CFLAGS
   export CFLAGS="-I/usr/include/lua5.3"
   export LDFLAGS="-llua5.3"
   ```

2. **链接错误**：
   确保在编译命令中包含 `-llua` 或 `-llua5.3`

### 运行时问题

1. **Lua 脚本不执行**：
   - 检查脚本语法：`lua lua_rules/test_rules.lua`
   - 确保函数名正确：`syscall_<name>`
   - 添加调试输出

2. **段错误**：
   - 使用 GDB 调试：
     ```bash
     gdb --args ./qemu-x86_64 --rules lua_rules ./test_program
     ```

3. **查看 Lua 状态**：
   在 `execute_lua_syscall_hook()` 函数开始处添加打印：
   ```c
   fprintf(stderr, "Checking Lua hook for syscall %d (%s)\n", num, syscall_name);
   ```

## 性能测试

创建性能测试程序：

```c
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define ITERATIONS 1000000

int main() {
    clock_t start, end;
    double cpu_time_used;

    start = clock();
    for (int i = 0; i < ITERATIONS; i++) {
        getpid();
    }
    end = clock();

    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Time for %d getpid calls: %f seconds\n", ITERATIONS, cpu_time_used);
    printf("Average time per call: %f microseconds\n",
           (cpu_time_used * 1000000) / ITERATIONS);

    return 0;
}
```

比较有/无 Lua 钩子的性能：
```bash
# 无 Lua 钩子
./qemu-x86_64 ./perf_test

# 有 Lua 钩子但不拦截
./qemu-x86_64 --rules lua_rules_empty ./perf_test

# 有 Lua 钩子且拦截
./qemu-x86_64 --rules lua_rules ./perf_test
```

## 扩展系统调用支持

要添加更多系统调用名称映射，编辑 `linux-user/syscall.c` 中的 `get_syscall_name()` 函数：

```c
static const char *get_syscall_name(int num)
{
    switch (num) {
    // ... existing cases ...

#ifdef TARGET_NR_your_syscall
    case TARGET_NR_your_syscall: return "your_syscall";
#endif

    // ... rest of cases ...
    }
}
```

然后重新编译 QEMU。

## 常见用例示例

### 1. 文件访问监控
```lua
function syscall_open(num, pathname, flags, mode, ...)
    -- 记录所有文件打开操作
    c_log(string.format("File opened: 0x%x", pathname))
    return 0, 0
end
```

### 2. 网络活动监控
```lua
function syscall_connect(num, sockfd, addr, addrlen, ...)
    c_log(string.format("Network connection: sockfd=%d", sockfd))
    return 0, 0
end
```

### 3. 进程行为分析
```lua
local fork_count = 0

function syscall_fork(num, ...)
    fork_count = fork_count + 1
    c_log(string.format("Fork #%d detected", fork_count))
    return 0, 0
end
```

## 故障排除

如果遇到问题，请检查：

1. Lua 库版本兼容性（推荐 Lua 5.3 或 5.4）
2. 系统调用名称映射是否正确
3. Lua 脚本语法是否正确
4. 返回值格式是否符合规范（两个整数）
5. QEMU 是否正确链接了 Lua 库

## 参考资源

- QEMU 文档: https://www.qemu.org/docs/master/
- Lua C API: https://www.lua.org/manual/5.3/manual.html#4
- Linux 系统调用: `man 2 syscalls`
