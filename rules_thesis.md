# SFEmu 规则全集与沉淀说明（毕设报告版）

> 版本：2026-02-11（基于当前仓库 `rules_examples/`、`lab/run_batch_001.sh`）
> 目的：给毕业设计报告提供“可直接引用”的规则体系说明，包括规则分层、触发条件、实现位置与实验落地方式。

---

## 1. 规则体系总览

### 1.1 三层规则架构

SFEmu 当前采用“三层规则 + 两个插件”的体系：

1. **基础规则层（Baseline）**
   - 目录：`rules_examples/syscall/*.lua`
   - 作用：处理高频 syscall 兼容问题（文件缺失、设备缺失、bind 失败、NVRAM 等）

2. **固件覆盖层（User Override）**
   - 目录：`rules_examples/syscall_override_user/*.lua`
   - 作用：承载型号特异性规则，不污染通用基线

3. **AI/临时覆盖层（AI Override）**
   - 目录：`rules_examples/syscall_override/*.lua`
   - 作用：运行期自动生成或手工临时验证的规则

4. **通性插件层（Commonfix 插件）**
   - 目录：`rules_examples/plugins/commonfix/init.lua`
   - 作用：在进程入口前做“跨品牌高频问题”的一次性修补

5. **启动反推插件层（Sysinfer 插件）**
   - 目录：`rules_examples/plugins/sysinfer/init.lua`
   - 作用：基于 syscall 证据回推启动命令、前置进程与参数

规则加载入口：`rules_examples/entry.lua`。默认优先级：

- `syscall_override_user` > `syscall_override` > `syscall`

可用 `SFEMU_RULES_OVERRIDE_DIR` 进行覆盖。

---

## 2. 通用 syscall 规则（默认规则）

> 以下规则默认放在 `rules_examples/syscall/`，用于“通性问题”兜底。

### 2.1 `open.lua` / `openat.lua`

- **问题类型**：路径缺失、父目录不存在、`/dev/nvram` 与 `/proc/mtd`、`/dev/mtd*` 缺失。
- **核心动作**：
  - `O_CREAT` 时自动补父目录；
  - `/dev/nvram` 映射到安全 fd（配合 NVRAM 逻辑层）；
  - `/proc/mtd`、`/dev/mtd*` 读缺失时映射到可用 fd 保证流程前进。
- **价值**：显著降低 `ENOENT` 早退与启动脚本断链。

### 2.2 `read.lua`

- **问题类型**：程序读取伪设备时拿不到可解析数据。
- **核心动作**：
  - 对 `/proc/mtd` 提供最小可解析文本；
  - 对 `/dev/mtd*` 提供有界数据并支持 EOF；
  - 结合 NVRAM 模块处理 `/dev/nvram` 协议读。
- **价值**：避免读取循环死等和配置解析失败。

### 2.3 `write.lua`

- **问题类型**：NVRAM 写入路径不一致或落盘失败。
- **核心动作**：
  - 接管 NVRAM 协议写（如 `key=value\0`）；
  - 统一写入 NVRAM 虚拟存储。
- **价值**：保证后续 `nvram_get` 可见一致状态。

### 2.4 `ioctl.lua`

- **问题类型**：私有设备 ioctl 在仿真中失败。
- **核心动作**：
  - NVRAM 相关 ioctl 返回最小合法结果；
  - D-Link 高频 ioctl（如 LAN IP 获取）提供兜底写回。
- **价值**：减少配置链路因 `ENOTTY/EINVAL` 中断。

### 2.5 `mmap.lua` / `mmap2.lua`

- **问题类型**：NVRAM 映射区域失配，导致空指针或越界。
- **核心动作**：
  - 为 NVRAM 提供可用映射和一致地址空间语义；
  - 配合端序处理避免 MIPS 大端崩溃。
- **价值**：降低 `SIGSEGV`（尤其 MIPS 大端）。

### 2.6 `lseek.lua`

- **问题类型**：伪设备读偏移语义错误。
- **核心动作**：维护 `/proc/mtd` 等伪文件的偏移一致性。
- **价值**：避免程序多次解析同一块数据导致异常行为。

### 2.7 `bind.lua`

- **问题类型**：服务绑定 `lan_ipaddr` 时返回 `EADDRNOTAVAIL`，导致 no_listen。
- **核心动作**：
  - IPv4 失败后回退到 `0.0.0.0`；
  - IPv6 失败后回退到 `::`。
- **价值**：显著提升 HTTP 监听成功率。

### 2.8 `connect.lua`

- **问题类型**：`/dev/log`、本地 socket 缺失导致异常退出。
- **核心动作**：与 fakefile 插件协同提供最小可连接语义。
- **价值**：减少 syslog 依赖导致的提前退出。

### 2.9 `socket.lua`

- **问题类型**：私有 netlink/socket 协议不兼容。
- **核心动作**：对高频协议做最小前进性兜底。
- **价值**：避免初始化阶段直接失败。

### 2.10 `close.lua` / `close_range.lua`

- **问题类型**：清 fd 阶段误伤内部 fd。
- **核心动作**：对关键 fd 做保护与映射表维护。
- **价值**：提升 daemonize/重启流程稳定性。

### 2.11 `execve.lua` / `execveat.lua`

- **问题类型**：启动链路不可观测，难以定位前置进程缺失。
- **核心动作**：记录 exec 命令行与参数证据（默认不改行为）。
- **价值**：为 syscall 反推插件提供证据。

### 2.12 `kill.lua` / `reboot.lua`

- **问题类型**：固件异常触发重启或进程自杀影响实验连续性。
- **核心动作**：限制破坏性行为对实验进程的影响。
- **价值**：保持仿真窗口可观测、可复盘。

---

## 3. 基础模块（`rules_examples/base/`）

### 3.1 `nvram.lua`（NVRAM 核心）

- 统一 NVRAM 键值读写语义；
- 兼容 `/dev/nvram` 与 libnvram 文件式访问；
- 处理 MIPS 大端/小端 u32 编码差异；
- 与 `nvram_defaults.lua` 联动提供默认键。

### 3.2 `nvram_defaults.lua`（默认键策略）

- 提供关键启动键的安全默认值（如 HTTP 开关、LAN 参数等）；
- 减少空键导致的 NULL 分支和 no_listen。

### 3.3 `mtd.lua`（Flash 伪设备）

- 提供 `/proc/mtd` 与 `/dev/mtd*` 的最小可解析语义；
- 采用“有限读取 + EOF”防止读取死循环。

### 3.4 `bootstrap_fs.lua`（启动前文件系统补齐）

- 补齐 `/var/run`、`/var/lock`、`/tmp/etc` 等目录；
- 补齐 SSL 证书模板（`config/ssl/`）；
- 解决证书缺失导致的 Web 服务提前退出。

### 3.5 `fdmap.lua`

- 建立“真实 fd ↔ 语义 fd（如 /dev/nvram）”映射；
- 让后续规则可精确识别 fd 对应资源。

### 3.6 `kvcollect.lua`

- 从 syscall 流中收集 NVRAM key；
- 输出到 `SFEMU_NVRAM_KEYS_FILE`（默认 `<LAB_DIR>/nvram_keys.syscall.txt`）；
- 为后续默认值推断提供输入。

### 3.7 `net.lua` / `netlink.lua` / `socket_server.lua`

- 提供网络前进性工具函数；
- 支撑 socket/bind/connect 等规则的共享能力。

### 3.8 `env.lua` / `util.lua` / `log.lua` / `sftrace.lua` / `ioctl_table.lua`

- 负责配置加载、通用工具、结构化日志、trace 与 ioctl 编码辅助。

---

## 4. 插件化规则

### 4.1 `plugins/commonfix/init.lua`（通性插件）

- 启动前自动执行，覆盖跨品牌高频问题：
  - `nobody` 账号补齐；
  - lighttpd 基础配置与目录修复；
  - 兼容软链补齐；
  - D-Link 常见配置链路补丁。
- 定位：将“跨固件可复用但不适合写入单个 syscall”的逻辑上收为插件。

### 4.2 `plugins/sysinfer/init.lua`（系统调用反推插件）

- 输入：`open/openat/execve/execveat` 实时证据；
- 输出：
  - `startup_args.syscall.guest.json`
  - `startup_prepend.syscall.guest.txt`
  - `startup_infer.report.json`
- 主要用途：
  - 发现“静态启动序列遗漏的前置进程”；
  - 自动推断 `httpd.cfg` 相关链路（如 D-Link `xmldb/xmldbc` 前置）。

### 4.3 `plugins/fakefile/init.lua`（缺失资源框架）

- 为缺失文件/设备/socket 提供最小行为模拟；
- 与 syscall 规则协同工作，避免脚本早退。

### 4.4 `plugins/ai/ai_mcp_openai.py`（AI 可选）

- 在异常退出/死循环触发时生成 patch 建议；
- 默认可关闭，避免批量跑时产生额外成本和不确定改动。

---

## 5. 批量仿真脚本中的“非 Lua 规则化能力”

> 除 Lua 外，`lab/run_batch_001.sh` 里还固化了大量与成功率直接相关的工程规则。

### 5.1 启动序列执行规则

- `SEQ_STARTUP=1` 时按 `startup_order` 分段启动：
  - 前置进程先起；
  - 固定等待 `SEQ_STAGE_DELAY_SECS`（默认 10 秒）；
  - 再起后置进程（目标服务）。

### 5.2 启动参数融合规则

- 静态参数：`startup_args.guest.json`（SDGen 反推）；
- 动态参数：`startup_args.syscall.guest.json`（sysinfer 反推）；
- 合并输出：`startup_args.effective.guest.json`。

### 5.3 D-Link 专项上收规则

- `httpd` 与 `httpcfg.php` 链路补全（`xmldb/xmldbc` 前置）；
- `nvram_daemon` 前置启动与 pid 文件补齐；
- BusyBox applet 语义保真（避免错误地直接执行 `busybox`）。

### 5.4 NVRAM/FirmAE 融合开关

- 支持按品牌启用 `libnvram` 注入；
- 支持基于 syscall 收集 key 后推断默认值文件再重跑；
- 通过 `LIBNVRAM_*` 系列参数统一控制。

### 5.5 Web 服务兜底规则

- `curl` 失败可触发静态 Web fallback；
- 有效提升“服务已起但页面链路非完整”的可用性统计。

---

## 6. 规则沉淀流程（可写进方法章节）

1. **每 10 个固件**统计失败类型（`curl_failed/no_listen/sigsegv/...`）。
2. 判断是否具有跨品牌共性：
   - 是：上收到 `syscall/*` 或 `plugins/commonfix`；
   - 否：落在 `syscall_override_user`。
3. 用小批次回归验证后再进入全量批次。
4. 将新规则与触发证据记录到 `rules.m`。

---

## 7. 报告可直接引用的结论

- 规则体系采用“**通用基线 + 型号覆盖 + 插件化扩展**”三层结构，支持持续迭代且可追溯。
- 启动成功率提升的关键不在单点 hack，而在“**启动序列 + 参数推断 + NVRAM + 设备缺失兜底**”的组合策略。
- 系统调用反推（sysinfer）是静态分析的重要补全路径，能够纠正“仅靠静态依赖图仍遗漏前置进程”的问题。
- NVRAM 的稳定实现必须同时覆盖：键值默认、端序、ioctl 语义、文件式访问四个层次。

---

## 8. 关键文件索引（便于查阅）

- 入口：`rules_examples/entry.lua`、`rules_examples/finish.lua`
- 通用规则：`rules_examples/syscall/*.lua`
- 基础能力：`rules_examples/base/*.lua`
- 通性插件：`rules_examples/plugins/commonfix/init.lua`
- 启动反推：`rules_examples/plugins/sysinfer/init.lua`
- 批量执行器：`lab/run_batch_001.sh`
- 规则沉淀日志：`rules.m`

