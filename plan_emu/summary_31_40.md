# 批次总结：31-40

时间：2026-01-31  
脚本：`lab/run_batch_001.sh`（`EMU_ONLY=1`，`DOCKER_WAIT_SECS=90`）

## 1. 结果总览

- 成功：6/10
- 失败：4/10

## 2. 逐个固件结果

| # | 品牌目录 | 固件 | Web 服务程序 | 架构 | 结果 | 证据 |
|---:|---|---|---|---|---|---|
| 31 | dlink | DCS-935L_REVA_FIRMWARE_1.04.06 | `web/httpd` | mips | ✅ | `success.url=http://127.0.0.1:80/` |
| 32 | dlink_ipcamera | DCS-935L_REVA_FIRMWARE_PATCH_v1.11.01_BETA | `web/httpd` | mips | ✅ | `success.url=http://127.0.0.1:80/` |
| 33 | dlink_latest | COVR-3902_REVA_ROUTER_FIRMWARE_v1.01B05 | `sbin/httpd` | arm | ❌ | 日志大量 `close ret=-9`（EBADF）重复，无监听（`ss.lntp.txt` 为空） |
| 34 | linksys_latest | FW_E1550_1.0.03.002_US_20120201_code | `usr/sbin/httpd` | mipsel | ✅ | `success.url=http://127.0.0.1:80/` |
| 35 | netgear | DGN1000NA_V1.1.00.40 | `usr/sbin/mini_httpd` | mips | ✅ | `success.url=http://192.168.0.1:80/` |
| 36 | netgear_latest | DST6501-V1.0.1.6 | `usr/sbin/mini_httpd` | arm | ❌ | 固件脚本反复输出 `sh: ln: not found`，未监听（`ss.lntp.txt` 为空） |
| 37 | tplink | ArcherC7_KR__V2_170215 | `usr/bin/httpd` | mips | ✅ | `success.url=http://192.168.0.1:80/` |
| 38 | tplink_ipcamera | NC230_v1.3.0_171205 | `sbin/lighttpd` | mipsel | ❌ | `qemu-mipsel: Could not open '/lib/ld-uClibc.so.0'`（rootfs 缺动态链接器） |
| 39 | tplink_latest | Archer_C1200_US__V2_180117 | `usr/sbin/uhttpd` | arm | ✅ | `success.url=http://127.0.0.1:80/` |
| 40 | trendnet_latest | TEW-430APB_2.12b02 | `bin/httpd` | mips | ❌ | 仅输出 Lua 初始化信息，无后续 syscall/监听（`ss.lntp.txt` 为空） |

## 3. 成功原因（共性）

- **参数兜底生效**：
  - `web/httpd` 自动补齐端口参数 `80`（否则会打印 usage 并退出），因此 31/32 成功。
  - `uhttpd` 自动补齐 `-p 0.0.0.0:80 -h /www`，因此 39 成功。
- **“伪只读 rootfs”修复**：
  - 新增对 `/etc -> /dev/null` 的通用修复（改指向 `/tmp/etc` 并补最小 `TZ/passwd`），使 35（DGN1000NA）从“/etc 不可用→退出”恢复为可提供 HTTP 回包。
- **批量入口稳定**：容器侧直接 `chroot` 执行 `qemu-* + Web 服务`，避免依赖固件 `/bin/sh`。

## 4. 失败原因分类（共性）

- **rootfs 缺关键运行时组件**：
  - 缺动态链接器（NC230：`/lib/ld-uClibc.so.0`）→ 动态程序无法启动。
- **固件脚本/工具链残缺**：
  - `ln` 缺失导致初始化脚本失败（DST6501）。
- **目标程序逻辑卡住/未进入 listen**：
  - COVR-3902 Router：日志高频 `close(-EBADF)`，疑似异常路径自旋，未监听端口。
  - TEW-430APB：仅初始化输出，无进一步 syscall/监听（需后续单固件深挖）。

## 5. 本批次沉淀的通性修复（基线）

- `lab/run_batch_001.sh`：
  - `chroot` 前对 `/dev` `/proc` `/sys` mountpoint 做 **symlink 解析**（避免 `/dev -> /dev/null` 导致 bind mount 失败）。
  - 对 `/etc -> /dev/null` 做 **通用修复**（改为 `/etc -> /tmp/etc`，并补最小 `TZ/passwd`）。

