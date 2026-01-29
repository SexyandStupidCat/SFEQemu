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

#### 失败固件的共同特征（首轮观察）

- `httpd` 进程完成了 NVRAM/SSL 初始化并写入 `/var/run/httpd.pid`，随后日志停滞（可能进入未映射 syscall 或用户态忙等）。
- 当前 `linux-user/syscall.c:get_syscall_name()` 仅白名单少量 syscall，很多 syscall 名为 `nil` 时 entry/finish 不落盘，导致排查盲区。

（每个固件的结果将记录：启动命令、curl 结果、关键错误点、是否新增“通用规则/固件特定规则”。）
