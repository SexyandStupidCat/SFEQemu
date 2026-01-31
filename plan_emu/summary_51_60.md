# 批次总结：51-60

时间：2026-01-31  
脚本：`lab/run_batch_001.sh`（`EMU_ONLY=1`，`DOCKER_WAIT_SECS=90`）

## 1. 结果总览

- 成功：7/10
- 失败：3/10

## 2. 逐个固件结果

| # | 品牌目录 | 固件 | Web 服务程序 | 架构 | 结果 | 证据/现象 |
|---:|---|---|---|---|---|---|
| 51 | tplink_ipcamera | NC250_v1.0.10_160321 | `sbin/lighttpd` | mipsel | ❌ | `qemu-mipsel: Could not open '/lib/ld-uClibc.so.0'`（缺动态链接器） |
| 52 | tplink_latest | Archer_C1200_V3_180122 | `usr/sbin/uhttpd` | arm | ✅ | `success.url=http://127.0.0.1:80/` |
| 53 | trendnet_latest | TEW-432BRP_3.10B20 | `bin/boa` | mips | ❌ | 初始：打开 `/dev/mtd` 报 `ENOENT`；后续已上收 MTD 兜底（`/dev/mtd*` 可打开），但仍触发 `SIGSEGV`（`qemu: uncaught target signal 11`） |
| 54 | ZyXEL_latest | MultyX_WSQ50__V2.00_ABKJ.5_C0 | `usr/sbin/lighttpd` | arm | ✅ | `success.url=http://127.0.0.1:80/` |
| 55 | asus_latest | FW_RT_AC1200GU_300438010528 | `usr/sbin/httpd` | mipsel | ✅ | `success.url=http://127.0.0.1:80/` |
| 56 | belkin_latest | F9J1102_WW_2.03.11 | `usr/sbin/httpd` | mipsel | ✅ | `success.url=http://127.0.0.1:80/` |
| 57 | dlink | DCS-935L_REVA_FIRMWARE_1.06.B02 | `web/httpd` | mips | ✅ | `success.url=http://127.0.0.1:80/` |
| 58 | dlink_ipcamera | DCS-960L_REVA_FIRMWARE_v1.06B01 | `web/httpd` | mips | ✅ | `success.url=http://127.0.0.1:80/` |
| 59 | dlink_latest | DIR-412_REVA_FIRMWARE_v1.14B02 | `sbin/httpd` | mipsel | ❌ | 日志大量 `close(-EBADF)`，无 TCP 监听（`ss.lntp.txt` 为空） |
| 60 | linksys_latest | FW_E2500_2.0.00.001_US_20140417 | `usr/sbin/httpd` | mipsel | ✅ | `success.url=http://127.0.0.1:80/` |

## 3. 失败原因分类（共性）

- **rootfs 缺动态链接器**：`/lib/ld-uClibc.so.0` 缺失导致 lighttpd 无法启动（51）。
- **缺失 MTD 设备/flash 信息**：`/dev/mtd` 缺失时 boa 走异常路径（53）。
- **程序异常自旋**：部分 dlink `httpd` 进入 `close(-EBADF)` 高频循环且不 `listen()`（59）。
