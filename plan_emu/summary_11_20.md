# 批次总结：11-20

时间：2026-01-31  
脚本：`lab/run_batch_001.sh`（`EMU_ONLY=1`，`DOCKER_WAIT_SECS=90`）

## 1. 结果总览

- 成功：2/10
- 失败：8/10

## 2. 逐个固件结果

| # | 品牌目录 | 固件 | Web 服务程序 | 架构 | 结果 | 关键现象/证据 |
|---:|---|---|---|---|---|---|
| 11 | tplink_ipcamera | NC200_v2.1.8_171109 | `sbin/lighttpd` | mipsel | ❌ | `chroot: failed to run command '/start.sh': No such file or directory`（多为 `/bin/sh` 缺失） |
| 12 | tplink_latest | 201092016340219 | `usr/bin/httpd` | mips | ❌ | `unset variable: SCRIPT_PATH%/*`（固件 shell 对参数展开不兼容） |
| 13 | trendnet_ipcamera | FW_TV-IP201W_-IP201_201W | `camera/http/webs` | mipsel | ❌ | `chroot: ... Permission denied`（`/bin/sh` 损坏/不可执行） |
| 14 | trendnet_latest | TEW-410APBplus_0.0.0 | `usr/sbin/httpd` | mipsel | ❌ | `unset variable: SCRIPT` / `SCRIPT_PATH=/start.sh: not found`（固件 shell 兼容性问题） |
| 15 | ZyXEL_latest | ARMOR_Z1__NBG6816__V1.00_AAWB.10_C0 | `usr/sbin/lighttpd` | arm | ❌ | `No configuration available. Try using -f option.`（lighttpd 需指定配置） |
| 16 | asus_latest | FW_BRT_AC828_30043807526 | `usr/sbin/httpd` | arm | ✅ | `success.url=http://127.0.0.1:80/` |
| 17 | belkin_latest | F7D4302-8302_WW_1.00.28 | `usr/sbin/httpd` | mipsel | ✅ | `success.url=http://127.0.0.1:80/` |
| 18 | dlink | DCS-932L_FIRMWARE_1.01 | `bin/goahead` | mipsel | ❌ | `please execute nvram_daemon first!`（缺前置 nvramd） |
| 19 | dlink_ipcamera | DCS-8200LH_REVA_FIRMWARE_1.02.03 | `web/httpd` | mips | ❌ | `Usage: httpd [Port] [AuthType]`（需要启动参数） |
| 20 | dlink_latest | COVR-3902...v1.01B02 | `sbin/httpd` | arm | ❌ | 无回包/无监听（`ss.lntp.txt` 为空；`stderr` 无明确报错） |

## 3. 失败原因分类（共性）

### 3.1 `/bin/sh` 缺失/损坏/不兼容 → 无法执行 `/start.sh`

- 表现：
  - `chroot: failed to run command '/start.sh': No such file or directory`（多数是 shebang 指向的 `/bin/sh` 不存在）
  - `Permission denied`（`/bin/sh` 存在但不可执行/损坏）
  - `unset variable ...` / `... not found`（固件 shell 语法能力不足，无法解析我们注入的脚本逻辑）
- 代表：NC200、FW_TV-IP201W、TEW-410APBplus、201092016340219。

### 3.2 Web 服务需要显式配置/参数

- `lighttpd`：报 `No configuration available. Try using -f option.`  
  - 代表：ARMOR_Z1（存在 `/etc/lighttpd/lighttpd.conf` 但启动命令未带 `-f`）。
- `web/httpd`：打印 usage 并退出  
  - 代表：DCS-8200LH（需要 `httpd 80` 或 `httpd 80 0/1`）。

### 3.3 goahead 依赖 nvram_daemon

- 代表：DCS-932L_FIRMWARE_1.01（同系列 1.00 也复现）。

## 4. 本批次结论与下一步“通性修复”方向

> 本批次暴露出的主要瓶颈不在 syscall 细节，而在“启动入口”与“服务启动参数”：

- **启动入口通用修复（优先级最高）**：批量仿真不再依赖固件 `/bin/sh` 执行 `/start.sh`，改为在容器侧直接 `chroot` 执行 `qemu-*` + 目标 Web 服务（并在 `chroot` 前把 cwd 切到候选 webroot）。  
  这样可覆盖：
  - rootfs 无 shell
  - shell 语法不兼容
  - `/bin/sh` 文件损坏
- **服务参数通用修复**：
  - `lighttpd`：自动探测配置文件（`/etc/lighttpd/lighttpd.conf`、`/etc/lighttpd.conf` 等）并追加 `-f <conf>`
  - `web/httpd`：对少数“必须带端口参数”的 `httpd` 变体增加通用启动参数策略（优先 `80`，必要时再尝试 `80 0`）
- **goahead 前置依赖**：评估以“最小副作用”的方式伪造 `nvram_daemon` 就绪（例如提供 `/var/run/nvramd.pid` 与必要的 nvram 读写前进性），再观察是否能上收为通用规则。

