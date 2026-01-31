# 批次总结：21-30

时间：2026-01-31  
脚本：`lab/run_batch_001.sh`（`EMU_ONLY=1`，`DOCKER_WAIT_SECS=90`）

## 1. 结果总览

- 成功：6/10
- 失败：4/10

## 2. 逐个固件结果

| # | 品牌目录 | 固件 | Web 服务程序 | 架构 | 结果 | 证据 |
|---:|---|---|---|---|---|---|
| 21 | linksys_latest | FW_E1500_v1.0.06.001_US_20140327_code | `usr/sbin/httpd` | mipsel | ✅ | `success.url=http://127.0.0.1:80/` |
| 22 | netgear | AC1450-V1.0.0.34_10.0.16 | `usr/sbin/httpd` | arm | ❌ | `qemu: uncaught target signal 11 (SIGSEGV)` |
| 23 | netgear_latest | AC1450-V1.0.0.36_10.0.17 | `usr/sbin/httpd` | arm | ❌ | `qemu: uncaught target signal 11 (SIGSEGV)` |
| 24 | tplink | ArcherC2_KR__V1_170221 | `usr/bin/httpd` | mipsel | ❌ | 仅见 AF_UNIX socket 绑定（`/var/tmp/8`），未观察到网络监听（`ss.lntp.txt` 为空） |
| 25 | tplink_ipcamera | NC220_v1.3.0_180105 | `sbin/lighttpd` | mipsel | ❌ | `qemu-mipsel: Could not open '/lib/ld-uClibc.so.0'`（rootfs 缺动态链接器） |
| 26 | tplink_latest | Archer_C1200_US__V1_180123 | `usr/sbin/uhttpd` | arm | ✅ | `success.url=http://127.0.0.1:80/` |
| 27 | trendnet_latest | TEW-411BRPplus_2.07 | `usr/sbin/httpd` | mipsel | ✅ | `success.url=http://127.0.0.1:80/` |
| 28 | ZyXEL_latest | ARMOR_Z2__NBG6817__V1.00_ABCS.8_C0 | `usr/sbin/lighttpd` | arm | ✅ | `success.url=http://127.0.0.1:80/` |
| 29 | asus_latest | FW_RT_AC1200E_300438010574 | `usr/sbin/httpd` | mipsel | ✅ | `success.url=http://127.0.0.1:80/` |
| 30 | belkin_latest | F7D7302_WW_1.00.23 | `usr/sbin/httpd` | mipsel | ✅ | `success.url=http://127.0.0.1:80/` |

## 3. 成功原因（共性）

- **启动入口更鲁棒**：批量仿真在容器侧直接 `chroot` 执行 `qemu-* + Web 服务`，避免依赖固件 `/bin/sh`（缺失/损坏/语法不兼容导致的启动失败）。
- **服务启动参数兜底**：
  - `uhttpd`：默认补齐 `-p 0.0.0.0:80 -h /www`，避免 “No sockets bound”
  - `lighttpd`：自动补齐 `-f` 配置文件，并按 `include "conf.d/*.conf"` 补齐缺失 include 文件
- **文件系统可写性修复**：对 `/var -> /dev/null` 这类 rootfs 布局做最小修复，保证 `/var/run/*.pid` 可创建，避免 lighttpd/httpd 早退。

## 4. 失败原因分类（共性）

- **目标程序崩溃（SIGSEGV）**：Netgear `AC1450*` 仍高频崩溃，属于后续需要更深入 syscall/依赖定位的问题。
- **rootfs 缺动态链接器**：`/lib/ld-uClibc.so.0` 缺失时，动态链接程序无法启动（NC220）。
- **服务未绑定网络端口**：个别 `httpd` 变体只做 AF_UNIX 控制 socket 或依赖更完整的 init/配置，未观测到 TCP 监听（ArcherC2）。

## 5. 本批次沉淀的通性修复（默认规则/基线）

- `rules_examples/syscall/bind.lua`：对 AF_UNIX `bind()` 的路径父目录执行 `mkdir -p`，避免 ENOENT（提升一批“先建控制 socket 再起服务”的固件前进性）。
- `lab/run_batch_001.sh`：批量启动逻辑上收为通用能力：
  - 不再依赖固件 `/start.sh`（绕过坏 `/bin/sh`）
  - lighttpd：`-f` 自动配置 + include 文件缺失补齐
  - uhttpd：默认 `-p 0.0.0.0:80 -h /www`
  - /var：修复 `/var -> /dev/null` 等导致 `Not a directory` 的布局

