# 60 个目标固件批量仿真：最终汇总

时间：2026-01-31  
数据集清单：`/media/user/ddisk/Work/FirmAE/firmwares/dataset/targets_60_multibrand_websvc.txt`  
执行脚本：`lab/run_batch_001.sh`（批量基线 `EMU_ONLY=1 DOCKER_WAIT_SECS=90`；个别固件回归重跑 `DOCKER_WAIT_SECS=120`）

## 1. 总体结果

- 总计：60
- 成功：29（判定标准：容器内 `curl` 对目标服务端口有回包）
- 失败：31

阶段性总结（每 10 个一份）：

- `plan_emu/summary_01_10.md`
- `plan_emu/summary_11_20.md`
- `plan_emu/summary_21_30.md`
- `plan_emu/summary_31_40.md`
- `plan_emu/summary_41_50.md`
- `plan_emu/summary_51_60.md`

## 2. 按品牌目录统计

| 品牌目录 | 成功/总数 |
|---|---:|
| ZyXEL_latest | 4/5 |
| asus_latest | 4/5 |
| belkin_latest | 5/5 |
| dlink | 3/5 |
| dlink_ipcamera | 3/5 |
| dlink_latest | 0/5 |
| linksys_latest | 3/5 |
| netgear | 2/4 |
| netgear_latest | 0/4 |
| tplink | 1/4 |
| tplink_ipcamera | 0/4 |
| tplink_latest | 3/4 |
| trendnet_ipcamera | 0/1 |
| trendnet_latest | 1/4 |

## 3. 按 Web 服务类型统计（basename）

| 服务名 | 成功/总数 |
|---|---:|
| httpd | 20/39 |
| uhttpd | 3/3 |
| mini_httpd | 3/6 |
| lighttpd | 3/8 |
| goahead | 0/2 |
| boa | 0/1 |
| webs | 0/1 |

## 4. 失败原因 Top（轻量归因）

> 说明：优先使用 `<rootfs>/sfemu_lab/fail.reason`；不存在则对 `<rootfs>/sfemu_lab/chroot_start.stderr.log` 做窄匹配归因。

| 失败原因 | 数量 |
|---|---:|
| unknown | 15 |
| sigsegv（`uncaught target signal 11`） | 7 |
| missing_ln（`ln: not found`） | 4 |
| missing_ld_uclibc（缺 `/lib/ld-uClibc.so.0`） | 3 |
| bad_args_usage（参数/Usage） | 2 |

## 5. 通性问题与默认规则沉淀（截至本轮）

- NVRAM：`open/openat` 将 `/dev/nvram` 映射到 `/dev/zero`（`c_open_host`），并由 `rules_examples/base/nvram.lua` 接管 ioctl/mmap/read/write（避免 `-EBUSY/-EINVAL` 与 NULL 返回导致崩溃）。
- ASUS `http_enable`：默认值修正为 `0`（启用 HTTP），避免 `select(nfds=0)` 造成“不监听端口”的假卡死。
- Webroot/cwd：启动前自动 `cd /www`（或 `SFEMU_WEBROOT`），避免“`/` 有回包但全页面 404”。
- `open/openat + O_CREAT`：父目录缺失自动 `mkdir -p` 后放行原 syscall（例如 `/var/run/httpd.pid`）。
- `bind(AF_UNIX)`：父目录缺失自动 `mkdir -p`（避免 `ENOENT`）。
- MTD：对 `/proc/mtd`、`/dev/mtd*` 做最小兜底（映射到 `/dev/zero` + `read/lseek` 伪造内容）。注意：本轮回归重跑后，相关固件仍可能因自身 `SIGSEGV` 失败（见表格与批次总结说明）。
- `execve/execveat`：仅观测打印执行命令行，不做干预。
- `kill/reboot`：拦截危险 `kill/reboot`，避免固件误伤容器/仿真框架。

## 6. 逐固件结果表（60/60）

| # | 品牌目录 | 固件 | 服务 | qemu | 结果 | 证据（成功=URL；失败=原因） |
|---:|---|---|---|---|---|---|
| 1 | ZyXEL_latest | ARMOR_X1__WAP6806__V1.00_ABAL.6_C0 | mini_httpd | qemu-mipsel | ✅ | http://192.168.0.1:80/ |
| 2 | asus_latest | FW_BLUECAVE_300438432546 | httpd | qemu-mips | ❌ | sigsegv |
| 3 | belkin_latest | F7D4301-8301_WW_1.00.30 | httpd | qemu-mipsel | ✅ | http://127.0.0.1:80/ |
| 4 | dlink | DCS-932L_FIRMWARE_1.00 | goahead | qemu-mipsel | ❌ | missing_ln |
| 5 | dlink_ipcamera | DCS-8200LH_REVA_FIRMWARE_1.02.03 | httpd | qemu-mips | ❌ | bad_args_usage |
| 6 | dlink_latest | COVR-3902_REVA_EXTENDER_FIRMWARE_v1.01B02 | httpd | qemu-arm | ❌ | unknown |
| 7 | linksys_latest | FW_E1000_2.1.03.005_US_20140321 | httpd | qemu-mipsel | ❌ | unknown |
| 8 | netgear | AC1450-V1.0.0.34_10.0.16 | httpd | qemu-arm | ❌ | sigsegv |
| 9 | netgear_latest | AC1450-V1.0.0.36_10.0.17 | httpd | qemu-arm | ❌ | sigsegv |
| 10 | tplink | ArcherC2_KR__V1_170221 | httpd | qemu-mipsel | ❌ | unknown |
| 11 | tplink_ipcamera | NC200_v2.1.8_171109 | lighttpd | qemu-mipsel | ❌ | unknown |
| 12 | tplink_latest | 201092016340219 | httpd | qemu-mips | ❌ | unknown |
| 13 | trendnet_ipcamera | FW_TV-IP201W_-IP201_201W | webs | qemu-mipsel | ❌ | unknown |
| 14 | trendnet_latest | TEW-410APBplus_0.0.0 | httpd | qemu-mipsel | ❌ | unknown |
| 15 | ZyXEL_latest | ARMOR_Z1__NBG6816__V1.00_AAWB.10_C0 | lighttpd | qemu-arm | ❌ | unknown |
| 16 | asus_latest | FW_BRT_AC828_30043807526 | httpd | qemu-arm | ✅ | http://127.0.0.1:80/ |
| 17 | belkin_latest | F7D4302-8302_WW_1.00.28 | httpd | qemu-mipsel | ✅ | http://127.0.0.1:80/ |
| 18 | dlink | DCS-932L_FIRMWARE_1.01 | goahead | qemu-mipsel | ❌ | missing_ln |
| 19 | dlink_ipcamera | DCS-8200LH_REVA_FIRMWARE_1.02.03 | httpd | qemu-mips | ❌ | bad_args_usage |
| 20 | dlink_latest | COVR-3902_REVA_EXTENDER_FIRMWARE_v1.01B02 | httpd | qemu-arm | ❌ | unknown |
| 21 | linksys_latest | FW_E1500_v1.0.06.001_US_20140327_code | httpd | qemu-mipsel | ✅ | http://127.0.0.1:80/ |
| 22 | netgear | AC1450-V1.0.0.34_10.0.16 | httpd | qemu-arm | ❌ | sigsegv |
| 23 | netgear_latest | AC1450-V1.0.0.36_10.0.17 | httpd | qemu-arm | ❌ | sigsegv |
| 24 | tplink | ArcherC2_KR__V1_170221 | httpd | qemu-mipsel | ❌ | unknown |
| 25 | tplink_ipcamera | NC220_v1.3.0_180105 | lighttpd | qemu-mipsel | ❌ | missing_ld_uclibc |
| 26 | tplink_latest | Archer_C1200_US__V1_180123 | uhttpd | qemu-arm | ✅ | http://127.0.0.1:80/ |
| 27 | trendnet_latest | TEW-411BRPplus_2.07 | httpd | qemu-mipsel | ✅ | http://127.0.0.1:80/ |
| 28 | ZyXEL_latest | ARMOR_Z2__NBG6817__V1.00_ABCS.8_C0 | lighttpd | qemu-arm | ✅ | http://127.0.0.1:80/ |
| 29 | asus_latest | FW_RT_AC1200E_300438010574 | httpd | qemu-mipsel | ✅ | http://127.0.0.1:80/ |
| 30 | belkin_latest | F7D7302_WW_1.00.23 | httpd | qemu-mipsel | ✅ | http://127.0.0.1:80/ |
| 31 | dlink | DCS-935L_REVA_FIRMWARE_1.04.06 | httpd | qemu-mips | ✅ | http://127.0.0.1:80/ |
| 32 | dlink_ipcamera | DCS-935L_REVA_FIRMWARE_PATCH_v1.11.01_BETA | httpd | qemu-mips | ✅ | http://127.0.0.1:80/ |
| 33 | dlink_latest | COVR-3902_REVA_ROUTER_FIRMWARE_v1.01B05 | httpd | qemu-arm | ❌ | unknown |
| 34 | linksys_latest | FW_E1550_1.0.03.002_US_20120201_code | httpd | qemu-mipsel | ✅ | http://127.0.0.1:80/ |
| 35 | netgear | DGN1000NA_V1.1.00.40 | mini_httpd | qemu-mips | ✅ | http://192.168.0.1:80/ |
| 36 | netgear_latest | DST6501-V1.0.1.6 | mini_httpd | qemu-arm | ❌ | missing_ln |
| 37 | tplink | ArcherC7_KR__V2_170215 | httpd | qemu-mips | ✅ | http://192.168.0.1:80/ |
| 38 | tplink_ipcamera | NC230_v1.3.0_171205 | lighttpd | qemu-mipsel | ❌ | missing_ld_uclibc |
| 39 | tplink_latest | Archer_C1200_US__V2_180117 | uhttpd | qemu-arm | ✅ | http://127.0.0.1:80/ |
| 40 | trendnet_latest | TEW-430APB_2.12b02 | httpd | qemu-mips | ❌ | unknown |
| 41 | ZyXEL_latest | MultyPlus_WSQ60__V2.00_ABND.3_C0 | lighttpd | qemu-arm | ✅ | http://127.0.0.1:80/ |
| 42 | asus_latest | FW_RT_AC1200GPlus_300438250624 | httpd | qemu-arm | ✅ | http://127.0.0.1:80/ |
| 43 | belkin_latest | F9J1102-4_WW_1.00.10 | httpd | qemu-mipsel | ✅ | http://127.0.0.1:80/ |
| 44 | dlink | DCS-935L_REVA_FIRMWARE_1.04.06 | httpd | qemu-mips | ✅ | http://127.0.0.1:80/ |
| 45 | dlink_ipcamera | DCS-935L_REVA_FIRMWARE_PATCH_v1.11.01_BETA | httpd | qemu-mips | ✅ | http://127.0.0.1:80/ |
| 46 | dlink_latest | COVR-3902_REVA_ROUTER_FIRMWARE_v1.01B05 | httpd | qemu-arm | ❌ | unknown |
| 47 | linksys_latest | FW_E2100L_1.0.05.004_20120308_code | mini_httpd | qemu-mips | ❌ | sigsegv |
| 48 | netgear | DGN1000_1.1.00.55_NA | mini_httpd | qemu-mips | ✅ | http://192.168.0.1:80/ |
| 49 | netgear_latest | DST6501-V1.0.1.6 | mini_httpd | qemu-arm | ❌ | missing_ln |
| 50 | tplink | Archer_C2_KR__V1_160126 | httpd | qemu-mipsel | ❌ | unknown |
| 51 | tplink_ipcamera | NC250_v1.0.10_160321 | lighttpd | qemu-mipsel | ❌ | missing_ld_uclibc |
| 52 | tplink_latest | Archer_C1200_V3_180122 | uhttpd | qemu-arm | ✅ | http://127.0.0.1:80/ |
| 53 | trendnet_latest | TEW-432BRP_3.10B20 | boa | qemu-mips | ❌ | sigsegv |
| 54 | ZyXEL_latest | MultyX_WSQ50__V2.00_ABKJ.5_C0 | lighttpd | qemu-arm | ✅ | http://127.0.0.1:80/ |
| 55 | asus_latest | FW_RT_AC1200GU_300438010528 | httpd | qemu-mipsel | ✅ | http://127.0.0.1:80/ |
| 56 | belkin_latest | F9J1102_WW_2.03.11 | httpd | qemu-mipsel | ✅ | http://127.0.0.1:80/ |
| 57 | dlink | DCS-935L_REVA_FIRMWARE_1.06.B02 | httpd | qemu-mips | ✅ | http://127.0.0.1:80/ |
| 58 | dlink_ipcamera | DCS-960L_REVA_FIRMWARE_v1.06B01 | httpd | qemu-mips | ✅ | http://127.0.0.1:80/ |
| 59 | dlink_latest | DIR-412_REVA_FIRMWARE_v1.14B02 | httpd | qemu-mipsel | ❌ | unknown |
| 60 | linksys_latest | FW_E2500_2.0.00.001_US_20140417 | httpd | qemu-mipsel | ✅ | http://127.0.0.1:80/ |
