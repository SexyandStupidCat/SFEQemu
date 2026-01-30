# SFEmu 固件批量仿真实验记录（do.md）

> 约定：本文件记录“我做了什么、为什么这么做、结果是什么、下一步是什么”。  
> 数据集：`/media/user/ddisk/Work/FirmAE/firmwares/dataset`

## 0. 实验目标与成功标准

- 目标：用 SFEmu/SFEQemu 在 Docker 环境里仿真固件的 `httpd` 服务。
- 成功标准：容器内 `curl` 对目标端口有回包（HTTP/HTTPS 任一即可），并保存对应日志与规则。

## 1. 工具链与关键路径

- 预处理（启动序列/依赖图）：`/media/user/ddisk/Work/Project/SFEmu/SDGen/find_need.py`
  - 参考：`/media/user/ddisk/Work/Project/SFEmu/SDGen/run.sh`
- 静态分析（伪C/符号/依赖库）：`/media/user/ddisk/Work/Project/SFEmu/SFAnalysis/pyghidra_fw_analyze.py`
  - 参考：`/media/user/ddisk/Work/Project/SFEmu/SFAnalysis/run.sh`
- 仿真引擎（QEMU-user + Lua rules）：`/media/user/ddisk/Work/Project/SFEmu/SFEQemu`
- Docker 运行环境：`/media/user/ddisk/Work/Project/SFEmu/workspace/Dockerfile`

## 2. 批次规划

- 批次 001（ASUS + ARM + /usr/sbin/httpd）：`lab/batch_001_asus_arm_httpd.txt`
- 预期输出位置：
  - 每个固件 rootfs 内：`<rootfs>/sfemu_lab/`（保存 sdg/sfanalysis/运行日志/结果）
  - 本仓库内：按批次更新 `rules.md`（通用规则总结）

## 3. 执行记录（实时更新）

### 批次 001

- 时间：2026-01-29
- 进展：已完成 10 个固件的“注入 -> Docker 仿真 -> curl 验证”首轮跑通。

#### 关键变更（避免旧规则干扰）

- 问题：部分 rootfs 内残留历史 `rules_examples/syscall_override/*`（旧 AI 规则），会覆盖基线规则，导致例如：
  - `open`/`openat` 的补齐逻辑不生效（日志里 `intercepted=false`，且看不到 `[open.target]`）
  - `/dev/nvram` 相关 ioctl/mmap 未被命中，进而触发崩溃/异常
- 处理：在批量注入的 `rules_examples/config/env` 中固定：
  - `SFEMU_RULES_OVERRIDE_DIR=syscall_override_user`
  - 仅保留“人工 per-firmware override”，忽略历史 `syscall_override`（AI 临时产物）

#### 结果概览（以 curl 有回包为成功）

- success（3/10）：
  - `FW_BRT_AC828_30043807526`：`http://127.0.0.1:80/`
  - `FW_RT_AC1300GPLUS_30043808375`：`http://127.0.0.1:80/`
  - `FW_RT_AC1300UHP_30043808375`：`http://127.0.0.1:80/`
- fail（7/10）：未观测到 TCP listen（`ss.lntp` 空），curl 超时/无回包
  - `FW_RT_AC1200G_300438250624`
  - `FW_RT_AC1200GPlus_300438250624`
  - `FW_RT_AC1750_B1_300438432738`
  - `FW_RT_AC1900_300438432738`
  - `FW_RT_AC1900P_300438432738`
  - `FW_RT_AC1900U_300438432738`
  - `FW_RT_AC3100_300438432738`

#### 关键修复：ASUS 系列 `http_enable` 默认值错误导致“不监听端口”

- 时间：2026-01-30
- 现象：
  - 以上 7 个固件中，`httpd` 完成证书/初始化并写入 pidfile，但始终不 `listen()`（`ss -lntp` 空）
  - syscall 上可见 `select(nfds=0)` 反复出现（60s timeout 或 timeout==NULL），导致误判为“卡死/死循环”
- 根因（来自 `httpd` 的伪C）：部分 ASUS 固件的 `http_enable` 语义为 **0=启用，1=禁用**；之前 NVRAM 默认值给成了 `"1"`，
  导致 `httpd` 跳过 `bind()/listen()` 分支，最终进入 `nfds=0` 的 select 等待分支
- 修复（通用规则上收）：
  - 修改：`rules_examples/base/nvram.lua` 默认 `http_enable="0"`
  - 这属于“通性问题”，应作为基线规则/默认行为，而不是每固件单独 override
- 复测结果（7/7 success，均在容器内 `curl` 有回包）：
  - `FW_RT_AC1200G_300438250624`：`http://127.0.0.1:80/`
  - `FW_RT_AC1200GPlus_300438250624`：`http://127.0.0.1:80/`
  - `FW_RT_AC1750_B1_300438432738`：`http://127.0.0.1:80/`
  - `FW_RT_AC1900_300438432738`：`http://127.0.0.1:80/`
  - `FW_RT_AC1900P_300438432738`：`http://127.0.0.1:80/`
  - `FW_RT_AC1900U_300438432738`：`http://127.0.0.1:80/`
  - `FW_RT_AC3100_300438432738`：`http://127.0.0.1:80/`

#### 失败固件的共同特征（首轮观察）

- `httpd` 进程完成了 NVRAM/SSL 初始化并写入 `/var/run/httpd.pid`，随后日志停滞（可能进入未映射 syscall 或用户态忙等）。
- 当前 `linux-user/syscall.c:get_syscall_name()` 仅白名单少量 syscall，很多 syscall 名为 `nil` 时 entry/finish 不落盘，导致排查盲区。

#### 新发现：Web UI “根路径有回包但所有页面 404”

- 复现固件：`FW_RT_AC1300UHP_30043808375`
- 现象：
  - `/` 返回 200（JS 重定向到 `/QIS_wizard.htm?...`）
  - 但 `/QIS_wizard.htm`、`/images/*`、`/qis/*.css` 等全部 404
- 根因：ASUS `httpd/2.0` 会把“当前工作目录”当作 webroot，并用相对路径打开资源；我们原先在固件根目录启动，导致资源都找不到。
- 修复：
  - 生成的 `start.sh` 改为优先 `cd /www`（可用 `SFEMU_WEBROOT` 覆盖）
  - 同时把 `qemu-arm/-rules/-sfanalysis` 统一改为绝对路径，并保持 `-L` 指向固件根目录
  - 结果：`/QIS_wizard.htm`、`/images/favicon.png`、`/qis/qis_style.css` 均恢复 200。

（每个固件的结果将记录：启动命令、curl 结果、关键错误点、是否新增“通用规则/固件特定规则”。）

#### 复测：FW_RT_AC1300UHP_30043808375（确认 Web UI 不再 404）

- 时间：2026-01-30
- 执行：
  - 通过脚本重新仿真并验证：`./lab/run_batch_001.sh lab/batch_single_rt_ac1300uhp.txt`
  - 额外手工验证关键页面/资源（在容器内 curl）：
    - `/` → 200（JS 重定向到 `/QIS_wizard.htm?flag=welcome`）
    - `/QIS_wizard.htm` → 200
    - `/Main_Login.asp` → 200
    - `/images/favicon.png` → 200
- 结果：
  - 监听：`0.0.0.0:80`（`ss -lntp` 可见 `qemu-arm` 监听）
  - 说明：该问题确认是“cwd/webroot”导致的假 404，`start.sh` 的 webroot 选择逻辑生效。

#### 新发现：宿主机访问端口映射后连接被重置/仿真进程崩溃

- 时间：2026-01-30
- 复现方式：
  - 使用 `DOCKER_PUBLISH=1` 把容器内的 80 映射到宿主机端口（例如 `18081:80`）
  - 宿主机 `curl http://127.0.0.1:18081/` 或浏览器访问 `/QIS_wizard.htm?...`
- 现象：
  - 容器内 `curl http://127.0.0.1:80/` 可成功（批量脚本判定为 success）
  - 但宿主机访问映射端口时常出现 `Connection reset by peer`，随后 `qemu-arm` 退出并生成 core（`qemu: uncaught target signal 11`）
- 根因定位：
  - privileged Docker 容器内自带真实字符设备 `/dev/nvram`（major=10 minor=144）
  - 固件 `httpd` 在处理请求时打开 `/dev/nvram`，但该设备在容器环境里 `open()` 返回 `-EBUSY/-EINVAL`
  - 触发固件异常路径并最终崩溃（表现为宿主机连接被重置、qemu/core dump）
- 修复：
  - QEMU 侧新增 Lua helper：`c_open_host()`（仅允许打开 `/dev/zero|/dev/null|/dev/urandom|/dev/random`）
  - 规则侧：`open/openat` 对 `/dev/nvram` 强制用 `c_open_host("/dev/zero", flags, mode)` 获取“安全 fd”，并在 `fdmap` 中标记为 `/dev/nvram`
  - 后续 `ioctl/mmap/read/write` 由 `rules_examples/base/nvram.lua` 接管，保证 nvram_get/nvram_set 前进性
  - 重新编译并同步 `qemu-arm`：`build-user-static/qemu-arm` → `/media/user/ddisk/Work/Project/SFEmu/workspace/rootfs/qemu-arm`
- 复测结果：
  - 宿主机访问 `http://127.0.0.1:18081/` 与 `http://127.0.0.1:18081/QIS_wizard.htm?flag=welcome` 均返回 200
  - 静态资源 `/images/favicon.png`、`/qis/qis_style.css` 也返回 200
  - 容器保持运行，未再出现访问即退出的情况
