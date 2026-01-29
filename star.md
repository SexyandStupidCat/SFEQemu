# SFEQemu / SFEmu：QEMU 改动与 Lua 规则说明（按问题归类）

本文档面向“把路由器固件（如 AX56U）的 `httpd` 跑起来并可访问”的实际需求，系统梳理：

- QEMU（本仓库）为了支持固件仿真/分析做了哪些关键改动（原理是什么）
- Lua rules（`rules_examples/`）是如何按“问题 → 解决方式”落地的（例如 NVRAM/WLCSM、netlink、证书等）

> 备注：本项目的核心理念是 **“不改固件二进制”**，把环境缺失/内核差异/外设缺失等问题，尽可能通过 **QEMU 用户态 syscall hook + Lua 规则** 来补齐或仿真。

---

## 1. 总体运行链路（从启动到请求）

典型启动链路：

1) Docker 提供一致的运行时（可选，但强烈推荐）
2) 在容器内挂载并 `chroot` 进入固件 rootfs（保证 `/proc`、`/dev`、`/sys`、`/tmp` 等正确）
3) 运行 `./start.sh` 启动 `qemu-arm`，由 QEMU 运行固件的 `/usr/sbin/httpd`
4) 通过 `curl http://127.0.0.1/` 访问（在“运行 httpd 的同一环境”内）

`start.sh`（固件 rootfs 内）常见参数含义：

- `-L .`：QEMU 用户态动态链接器前缀
- `-rules ./rules_examples/`：启用 Lua rules（本项目核心）
- `-rules-ctx-keep N`：保留 syscall 上下文，落盘到 `rules_examples/cache/`（用于复盘/定位）
- `-rules-idle-ms MS`：idle watchdog；长时间无 syscall 时触发前进性检查/死循环探测
- `-shadowstack ...`：启用 shadow call stack（供 Lua 拿到 backtrace）
- `-sfanalysis <dir>`：启用地址解析（guest/host addr → 模块/函数/伪 C），用于快速定位崩溃根因

---

## 2. QEMU 侧关键改动（解决“可插拔修复 + 可观测性”）

下面是“为了让 Lua 能介入固件 syscall 行为，并能做工程化定位”的核心改动点。

### 2.1 两阶段 syscall hook：`entry.lua` / `finish.lua`

**问题**：固件在用户态运行时会大量依赖内核/驱动/外设；如果直接让 syscall 失败，往往会“早退/卡死/崩溃”。我们需要一个可插拔的机制，在 syscall 前后做决策与观测。

**解决方式**：在 QEMU linux-user 侧对每次 syscall 做“两段式回调”：

- `entry.lua`：syscall 执行前调用，决定“是否拦截/替换返回值”
- `finish.lua`：syscall 执行后调用，统一记录 ret、是否被拦截、以及额外诊断信息

核心流程（简化）：

1. `do_syscall()` 收到 syscall
2. 调用 Lua 的 `entry(syscall_name, num, arg1..arg8)`  
   - 若返回 `need_change=true/1`：直接返回 Lua 提供的 `ret`，跳过真实 syscall
   - 否则：执行真实 syscall（`do_syscall1()`）
3. 调用 Lua 的 `finish(syscall_name, num, ret, intercepted, arg1..arg8)`

相关源码（便于追溯）：

- `linux-user/main.c`：新增命令行参数（`-rules*`、`-sfanalysis`、`-shadowstack`）
- `linux-user/syscall.c`：在 `do_syscall()` 前后调用 `execute_lua_syscall_entry()` / `execute_lua_syscall_finish()`

### 2.2 “按需加载 + 缓存”的 Lua 规则工程化结构

**问题**：固件 syscall 很多，如果每次都加载全部 Lua 脚本，会慢、难维护、也容易互相干扰。

**解决方式**：Lua rules 采用分层目录 + 按需加载：

- `rules_examples/entry.lua` 是总入口：负责分发/缓存/记录上下文/检测死循环等
- 具体 syscall 的规则放在 `rules_examples/syscall/<name>.lua`
- 允许 override（覆盖）目录，实现“快速迭代修复”而不污染基础规则

默认覆盖优先级（在 `entry.lua` 内实现）：

1. `syscall_override_user/<name>.lua`：人工快速迭代（本次 nvram/netlink 修复主要在这里）
2. `syscall_override/<name>.lua`：自动/AI/临时修复（例如 syslog `/dev/log` 兼容通常放在这里）
3. `syscall/<name>.lua`：基础规则

### 2.3 Lua 可调用的 C 能力（“能读/能写/能调用真实 syscall”）

**问题**：仅靠 syscall 参数整数值无法完成复杂修复；例如要解析 `msghdr/iovec`，必须读 guest 内存；要伪造 `recvmsg` 返回包，必须写 guest 内存；要做“真实调用 + 降级”也需要桥接真实 syscall。

**解决方式**：QEMU 向 Lua 注册了一组 C 函数（列表与用法已合并到 `rules_examples/README.md`），典型能力包括：

- `c_do_syscall(num, ...)`：执行真实 syscall（避免 Lua 拦截导致递归）
- `c_read_bytes` / `c_write_bytes`：读写 guest 内存字节（用于解析结构体与伪造返回值）
- `c_read_string`：读 guest 字符串
- `c_get_shadowstack`：拿到 shadowstack 回溯（依赖 `-shadowstack`）
- `c_resolve_addr` / `c_resolve_host_addr`：地址解析到模块/函数/伪 C（依赖 `-sfanalysis`）

这套能力是“规则能够从记录型，升级为修复/仿真型”的关键。

### 2.4 可观测性与前进性：`rules-ctx-keep` / `rules-idle-ms`

**问题**：固件常见失败形态不是直接崩溃，而是“卡住/无响应/反复重试”，如果没有上下文，很难判断卡在哪里、为什么。

**解决方式**：

- `-rules-ctx-keep N`：在 Lua `entry.lua` 侧保留最近 N 条 syscall 上下文并落盘到 `rules_examples/cache/`，用于复盘
- `-rules-idle-ms MS`：当长时间无 syscall 时，触发 idle watchdog；配合 `entry.lua` 的死循环检测逻辑可输出报告/执行探测

### 2.5 `shadowstack` 与 `sfanalysis`：用于快速定位根因

**问题**：固件崩溃时通常只有地址，没有符号；定位起来很慢。

**解决方式**：

- `-shadowstack`：维护 shadow call stack，Lua 可通过 `c_get_shadowstack()` 获取回溯地址列表
- `-sfanalysis <dir>`：启用 SFAnalysis 输出目录；可将地址解析到模块路径、函数名、函数原型、以及伪 C 文件路径（用于“从地址到根因”的闭环）

---

## 3. 规则层：按“问题 → 解决方式”归类（固件可跑的关键）

下面是本次让 `httpd` 跑起来过程中，真正影响“能否启动/能否监听端口/能否响应请求”的规则修复点。

### 3.1 NVRAM / WLCSM：`nvram_get()` 返回 NULL 导致 `httpd` 崩溃

**现象**：

- `httpd` 启动或处理请求时崩溃（典型是 `strcmp(NULL, "1")`）
- 根因是 `nvram_get("x_Setting")` 失败返回 `NULL`，而固件代码未判空

**解决方式**：仿真 WLCSM netlink 的 `nvram_get` 协议（最小实现），保证对关键键返回非空字符串。

实现位置（仓库侧与 rootfs 侧同步维护）：

- `rules_examples/syscall_override_user/sendmsg.lua`
- `rules_examples/syscall_override_user/recvmsg.lua`

**协议关键点（用于理解为什么能修复）**：

固件的 `libnvram.so` 通过 netlink 发送 WLCSM 消息：

- `nlmsg_type = 5`
- `cmd`：`u16`，位于 netlink payload 的 `0x10`（本实现关注 `cmd=3`，即 `nvram_get`）
- `data_len`：`u16`，位于 `0x12`
- `key`：从 payload `0x18` 起的一段 C 字符串（`\\0` 结尾）

我们的策略是：

1) `sendmsg`：识别 `cmd=3` 的请求，记录“待响应的 key”，并让 `sendmsg` 表现为成功  
2) `recvmsg`：构造一个符合 libnvram 解析习惯的“回复包”，把 `value` 写进 guest 的 iov 缓冲区并返回长度

**默认值策略**：

- `NVRAM_DEFAULTS` 至少包含 `x_Setting="1"`，用于避开固件“初始化未完成”的异常分支
- 未知 key 统一返回 `"0"`（注意不能返回空串，否则 libnvram 可能把“值长度=0”视为失败）

> 扩展建议：如果后续页面开始写 nvram，需要继续实现 `cmd=set/commit` 等写路径；目前的最小实现只保证 `nvram_get` 不崩且可启动 Web。

### 3.2 私有 netlink proto=31：宿主不支持导致 `httpd` 卡死/不监听端口

**现象**：

- 日志中反复出现 `can't send message: Operation not supported`
- 80 端口迟迟不监听（或很久才进入主循环）

**原因**：

固件创建 `socket(AF_NETLINK, SOCK_RAW, 31)`（私有协议号），在宿主内核环境下常不支持；
如果把错误原样返回，固件会进入循环重试/阻塞等待，导致初始化阶段卡住，Web 不起来。

**解决方式**：对该类 netlink fd 做“虚拟化兜底”（保证前进性）：

1) `socket.lua`：当检测到 `AF_NETLINK + SOCK_RAW + proto=31`  
   - 改用 `proto=0(NETLINK_ROUTE)` 创建一个可 bind 的 fd
   - 标记该 fd 为“虚拟 netlink”
2) `sendmsg.lua` / `recvmsg.lua`：
   - 对标记 fd 默认启用 `NETLINK_VIRTUAL_ACK`
   - `sendmsg`：丢弃发送但返回成功（并记录最近一次请求头部）
   - `recvmsg`：返回一个最小的 `NLMSG_ERROR(error=0)` ACK，让上层认为“请求已被处理”

实现位置：

- `rules_examples/syscall_override_user/socket.lua`
- `rules_examples/syscall_override_user/sendmsg.lua`
- `rules_examples/syscall_override_user/recvmsg.lua`

可配置开关：

- `SFEMU_NETLINK_VIRTUAL_ACK=0`：尽量走真实 netlink（不建议用于此固件启动；常会回到 `-EOPNOTSUPP` 的卡死态）

### 3.3 `/dev/log` syslog：缺失导致固件 early-exit

**现象**：

- 固件尝试 `connect("/dev/log")` 写 syslog
- 若失败，部分固件会直接 `exit_group`（日志系统被视为关键依赖）

**解决方式**：把 syslog 变成“黑洞但成功”：

- `connect`：当目标是 `/dev/log` 时强制返回成功，并把 fd 标记为 syslog fd
- `write` / `sendto` / `sendmsg`：对 syslog fd 丢弃数据，但返回“写入成功”的字节数

实现位置（在当前目录结构下，固件 rootfs 位于本仓库的 `../workspace/rootfs`；以下路径以此为基准）：

- `../workspace/rootfs/rules_examples/syscall_override/connect.lua`
- `../workspace/rootfs/rules_examples/syscall_override/write.lua`
- `../workspace/rootfs/rules_examples/syscall_override/sendto.lua`
- `../workspace/rootfs/rules_examples/syscall_override/sendmsg.lua`

### 3.4 证书/密钥缺失：OpenSSL 报错导致 `httpd` 退出

**现象**：

- OpenSSL 报错：`Expecting: TRUSTED CERTIFICATE` 等
- `httpd` 在初始化 HTTPS/证书时早退

**原因**：

固件 rootfs 解包后，`/etc/cert.pem`、`/etc/key.pem` 等可能缺失/为空/内容不合法；
若再被 “fakefile 占位文件” 覆盖，会进一步触发解析失败。

**解决方式**：

1) 启动前最小补齐：`bootstrap_fs` 自动补齐目录与证书
   - 创建 `/var/lock`、`/var/run`
   - 为部分脚本补 `chmod +x`（如 `gencert.sh`）
   - 将 `rules_examples/config/ssl/` 下内置证书写入 `/etc/{cert,key,server}.pem` 等
2) 避免误覆盖：`fakefile` 插件把证书路径列为“关键路径”，避免生成 fakefile 占位污染

实现位置：

- `rules_examples/base/bootstrap_fs.lua`
- `rules_examples/plugins/fakefile/init.lua`
- `rules_examples/config/ssl/`（内置证书/密钥，仅用于仿真环境）

### 3.5 启动脚本与 SFAnalysis 输出目录：目录不存在会导致 QEMU 异常退出

**现象**：

- 直接运行 `./start.sh` 时提示 `无法打开 SFAnalysis 输出目录: /out_...`
- 之后可能触发 QEMU 侧 `free(): invalid pointer` 或 `Segmentation fault`

**原因**：

`-sfanalysis` 指定了绝对路径 `/out_...`，但你是在容器里直接跑 `/rootfs/start.sh`（未 chroot），
此时绝对路径指向“容器根目录 `/`”，目录不存在就失败。

**解决方式**：

- `start.sh` 改为使用相对目录 `out_AX56U_httpd`，并 `mkdir -p` 自动创建
- 支持用环境变量 `SFANALYSIS_OUT_DIR` 覆盖输出目录名

实现位置：

- `../workspace/rootfs/start.sh`

### 3.6 Docker 工具缺失：容器内没有 `ip a`

**现象**：容器内 `ip: command not found`

**解决方式**：镜像安装 `iproute2`，确保容器内可直接 `ip a` 查看网络信息

实现位置：

- `docker/Dockerfile`

---

## 4. 推荐验证方式（可复现、可自动化）

### 4.1 正确启动（推荐在容器内 chroot）

在容器里执行（以 `/rootfs` 为 rootfs 挂载点）：

```bash
cd /rootfs
CHROOT_CMD="./start.sh" ./mount_and_chroot.sh
```

### 4.2 验证 Web 起来（在同一环境内）

```bash
curl -v http://127.0.0.1/
curl -v http://127.0.0.1/index.asp
```

> 注意：`127.0.0.1` 指的是 **运行 httpd 的同一环境**（容器/chroot 内），不是宿主机外部。

---

## 5. 已知现状与下一步（可选）

- 当前 `httpd` 已可稳定返回 `200 OK`（例如 `/`、`/index.asp`），但部分页面（如 `/Main_Login.asp`）仍可能 `404`。  
  这通常属于 **Web 路由/资源映射/鉴权逻辑** 的进一步对齐问题（页面文件存在于 `www/`，但 httpd 可能还有内部映射规则）。

如果要继续把完整 UI 跑通，建议按优先级推进：

1) 扩充 `NVRAM_DEFAULTS`（只在确实影响页面渲染/跳转时加，避免引入副作用）
2) 逐步补齐 WLCSM 的写路径（set/commit）与其它依赖服务（若页面开始写配置）
3) 追踪 `httpd` 访问页面时实际打开的路径（可在 `open/openat` 规则里加针对 `/www` 的日志）
