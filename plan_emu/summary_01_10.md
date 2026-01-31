# 批次总结：01-10

时间：2026-01-30 ～ 2026-01-31  
脚本：`lab/run_batch_001.sh`（`EMU_ONLY=1`，跳过 SDGen/SFAnalysis；`DOCKER_WAIT_SECS=90`）  
成功判定：容器内 `curl` 对任意 host/port 的 HTTP/HTTPS **有回包**（不要求 200；404 也算成功）

## 1. 结果总览

- 成功：2/10
- 失败：8/10

> 说明：每个固件的原始运行产物都在其自身 rootfs 下：`<rootfs>/sfemu_lab/`（`result.status`、`success.url`、`chroot_start.*`、`docker.*`、`curl_*`、`ss.lntp.txt`）。

## 2. 逐个固件结果

| # | 品牌目录 | 固件 | Web 服务程序 | 架构 | 结果 | 证据 |
|---:|---|---|---|---|---|---|
| 01 | ZyXEL_latest | ARMOR_X1__WAP6806__V1.00_ABAL.6_C0 | `bin/mini_httpd` | mipsel | ✅ | `success.url=http://192.168.0.1:80/` |
| 02 | asus_latest | FW_BLUECAVE_300438432546 | `usr/sbin/httpd` | mips | ❌ | `qemu: uncaught target signal 11 (SIGSEGV)`（见 `chroot_start.stderr.log`） |
| 03 | belkin_latest | F7D4301-8301_WW_1.00.30 | `usr/sbin/httpd` | mipsel | ✅ | `success.url=http://127.0.0.1:80/` |
| 04 | dlink | DCS-932L_FIRMWARE_1.00 | `bin/goahead` | mipsel | ❌ | `goahead: please execute nvram_daemon first!` 且 `sh: ln: not found` |
| 05 | dlink_ipcamera | DCS-8200LH_REVA_FIRMWARE_1.02.03 | `web/httpd` | mips | ❌ | 程序输出 `Usage: httpd [Port] [AuthType]` 后 `exit(4001)` |
| 06 | dlink_latest | COVR-3902_REVA_EXTENDER_FIRMWARE_v1.01B02 | `sbin/httpd` | arm | ❌ | 无回包（`ss.lntp.txt` 无有效监听/或监听端口不在探测范围） |
| 07 | linksys_latest | FW_E1000_2.1.03.005_US_20140321 | `usr/sbin/httpd` | mipsel | ❌ | 启动脚本/环境兼容性问题（见 `chroot_start.stderr.log`） |
| 08 | netgear | AC1450-V1.0.0.34_10.0.16 | `usr/sbin/httpd` | arm | ❌ | `qemu: uncaught target signal 11 (SIGSEGV)` |
| 09 | netgear_latest | AC1450-V1.0.0.36_10.0.17 | `usr/sbin/httpd` | arm | ❌ | `qemu: uncaught target signal 11 (SIGSEGV)` |
| 10 | tplink | ArcherC2_KR__V1_170221 | `usr/bin/httpd` | mipsel | ❌ | 无回包（需进一步定位启动参数/依赖） |

## 3. 成功原因（共性）

- **服务自身依赖少**：`mini_httpd/httpd` 这类“轻量 Web 服务”在缺少完整系统服务（nvramd、syslogd、rc 系统）时也可能直接起来。
- **基线规则保证前进性**：目录补齐（`open/openat + O_CREAT`）、`/dev/nvram` 最小可用仿真、禁止危险 `reboot/kill`，能显著减少“初始化失败→重启/退出”的早死情况。

## 4. 失败原因分类（共性）

### 4.1 目标程序崩溃（SIGSEGV）

- 现象：`qemu: uncaught target signal 11`，通常发生在初始化或处理请求阶段。
- 影响：即使短暂有回包，也可能在后续探测窗口内崩溃导致最终判定失败。
- 代表：`FW_BLUECAVE_300438432546`、`AC1450*`。

### 4.2 关键前置服务缺失（nvram_daemon / 运行时工具缺失）

- 现象：Web 服务明确要求 `nvram_daemon` 先启动；或依赖 `ln/dirname` 这类基础工具完成目录/链接准备。
- 代表：`DCS-932L_FIRMWARE_1.00`（`nvram_daemon` + `ln` 缺失）。

### 4.3 Web 服务需要启动参数/配置

- 现象：程序打印 usage 并直接退出（例如需要端口、认证模式）。
- 代表：`DCS-8200LH ... /web/httpd`（需要至少 `httpd 80`）。

### 4.4 无监听/未命中探测端口（表现为无回包）

- 现象：容器内 `ss -lntp` 看不到目标服务监听，或监听在非常规端口/绑定了特定地址导致探测失败。
- 代表：`COVR-3902 ... httpd`、`ArcherC2 ... httpd`（需后续批次进一步归因）。

## 5. 本批次沉淀到“默认规则”的通性修复

> 这些修复属于“跨固件通性问题”，已经上收为基线规则，后续批次直接受益。

- `rules_examples/syscall/kill.lua`：拦截 `kill(1, sig!=0)` / `kill(-1, sig!=0)` / `kill(0, SIGTERM/SIGKILL)`，避免固件 reboot/shutdown 脚本误杀容器关键进程导致“戛然而止”。
- `rules_examples/syscall/reboot.lua`：禁止 `reboot(2)`（初始化失败路径高频触发）。
- `rules_examples/entry.lua`：支持 `SFEMU_NO_PROMPT=1` 跳过人工确认，保证批量无人值守可跑完。
- `rules_examples/base/nvram.lua`：增强匿名映射兼容（`MAP_ANONYMOUS` 多候选）与 syscall 参数清理，降低跨架构 `mmap`/`read` 异常导致的早期崩溃概率。

