# 批次总结：41-50

时间：2026-01-31  
脚本：`lab/run_batch_001.sh`（`EMU_ONLY=1`，`DOCKER_WAIT_SECS=90`）

## 1. 结果总览

- 成功：6/10
- 失败：4/10

## 2. 逐个固件结果

| # | 品牌目录 | 固件 | Web 服务程序 | 架构 | 结果 | 证据/现象 |
|---:|---|---|---|---|---|---|
| 41 | ZyXEL_latest | MultyPlus_WSQ60__V2.00_ABND.3_C0 | `usr/sbin/lighttpd` | arm | ✅ | `success.url=http://127.0.0.1:80/` |
| 42 | asus_latest | FW_RT_AC1200GPlus_300438250624 | `usr/sbin/httpd` | arm | ✅ | `success.url=http://127.0.0.1:80/` |
| 43 | belkin_latest | F9J1102-4_WW_1.00.10 | `usr/sbin/httpd` | mipsel | ✅ | `success.url=http://127.0.0.1:80/` |
| 44 | dlink | DCS-935L_REVA_FIRMWARE_1.04.06 | `web/httpd` | mips | ✅ | `success.url=http://127.0.0.1:80/`（`/web/httpd` 端口参数兜底生效） |
| 45 | dlink_ipcamera | DCS-935L_REVA_FIRMWARE_PATCH_v1.11.01_BETA | `web/httpd` | mips | ✅ | `success.url=http://127.0.0.1:80/` |
| 46 | dlink_latest | COVR-3902_REVA_ROUTER_FIRMWARE_v1.01B05 | `sbin/httpd` | arm | ❌ | 大量 `close(-EBADF)` 后 `qemu: uncaught target signal 11 (SIGSEGV)` |
| 47 | linksys_latest | FW_E2100L_1.0.05.004_20120308_code | `usr/sbin/mini_httpd` | mips | ❌ | 初始：读取 `/proc/mtd` 报 `ENOENT`；后续已上收 MTD 兜底（`/proc/mtd` 可读），但仍触发 `SIGSEGV`（`qemu: uncaught target signal 11`） |
| 48 | netgear | DGN1000_1.1.00.55_NA | `usr/sbin/mini_httpd` | mips | ✅ | `success.url=http://192.168.0.1:80/` |
| 49 | netgear_latest | DST6501-V1.0.1.6 | `usr/sbin/mini_httpd` | arm | ❌ | 固件脚本反复输出 `sh: ln: not found`，未监听 |
| 50 | tplink | Archer_C2_KR__V1_160126 | `usr/bin/httpd` | mipsel | ❌ | 仅绑定 AF_UNIX 控制 socket（`/var/tmp/8`），未见 TCP 监听 |

## 3. 成功原因（共性）

- `web/httpd`/`uhttpd`/`lighttpd` 的**启动参数兜底**与**配置缺失补齐**策略持续生效。
- `mini_httpd` 在 Netgear DGN1000 系列上依赖较少，结合 `/etc`/`/var` 可写性修复，稳定出现回包。

## 4. 失败原因分类（共性）

- **程序崩溃（SIGSEGV）**：COVR-3902 Router（rootfs 版本）仍触发崩溃，属于需要单固件进一步定位的类别。
- **依赖 flash 信息（/proc/mtd）**：部分 Linksys `mini_httpd` 明确读取 `/proc/mtd`，在容器里为空会走异常路径并不监听。
- **运行时工具缺失**：`ln` 缺失导致初始化脚本无法完成（DST6501）。
- **服务模式差异**：部分 TP-Link `httpd` 先创建 AF_UNIX 控制 socket 后退出/等待其他前置（表现为无 TCP 监听）。
