# SFEmu 使用说明（单固件交互仿真）

本文档对应以下交付：

- 安装脚本：`scripts/install_sfemu_ubuntu24.sh`
- 启动脚本：`lab/start_single_interactive.sh`
- 规则总文档：`rules_thesis.md`

---

## 1. 在全新 Ubuntu 24.04 安装

在 `SFEQemu` 仓库根目录执行：

```bash
./scripts/install_sfemu_ubuntu24.sh
```

安装脚本会完成：

1. 安装系统依赖（Docker、Java、Python、QEMU 构建工具链）
2. 创建 Python 虚拟环境并安装 `pyghidra/jpype1/loguru`
3. 构建 `qemu-arm/qemu-mips/qemu-mipsel`
4. 复制 qemu 到 `../workspace/rootfs/`
5. 构建运行镜像 `sfemu-ubuntu2404:local`

> 若脚本提示你被加入了 `docker` 组，请重新登录一次终端会话。

---

## 2. 前置准备

建议在运行前确认：

1. 数据集 rootfs 已准备好（例如 FirmAE 解包后的 `rootfs`）。
2. 目标服务二进制路径已知（如 `/usr/sbin/httpd`、`/bin/goahead`）。
3. `GHIDRA_ROOT` 已设置（用于 SDGen/SFAnalysis）。

示例：

```bash
export GHIDRA_ROOT=/path/to/ghidra
source ../.venv-sfemu/bin/activate
```

---

## 3. 一条命令启动“静态分析 + 交互容器”

```bash
./lab/start_single_interactive.sh \
  --rootfs /abs/path/to/rootfs \
  --service /usr/sbin/httpd
```

脚本会自动完成三件事：

1. 调用 `lab/run_batch_001.sh` 执行 SDGen + SFAnalysis（单固件）
2. 在 `<rootfs>/<lab_name>/` 生成交互启动脚本
3. 启动 Docker 并进入交互 shell

---

## 4. 在容器里启动服务（按启动序列）

进入容器后执行：

```bash
/rootfs/<lab_name>/start_service_seq_in_container.sh
```

这个脚本会：

1. 挂载 `proc/sys/dev/tmp`
2. 加载启动序列（`startup_binaries.guest.txt`）
3. 按“前置进程 -> 等待 N 秒 -> 后置进程”分段启动
4. 应用 D-Link 常见前置链路补齐（`xmldb/nvram_daemon`）
5. 输出日志到：`/rootfs/<lab_name>/seq_manual/`

---

## 5. 成功判定与常用检查

### 5.1 服务是否监听

```bash
ss -lntp | grep -E '(:80|:443|:8080|qemu-)'
```

### 5.2 HTTP 回包验证

```bash
curl -v http://127.0.0.1/
```

> 以 `curl` 有回包作为仿真成功标准。

---

## 6. 常用参数

`lab/start_single_interactive.sh` 支持：

- `--lab-name <name>`：指定产物目录名
- `--image-tag <tag>`：指定 Docker 镜像
- `--seq-delay <sec>`：分段启动等待秒数
- `--force-sdgen`：强制重跑 SDGen
- `--force-sfanalysis`：强制重跑 SFAnalysis
- `--skip-sfanalysis`：跳过 SFAnalysis（仅验证动态链路）

---

## 7. 结果与文档位置

- 规则总文档（可用于论文）：`rules_thesis.md`
- 规则沉淀日志（时间线）：`rules.m`
- 行为记录：`do.md`
- 单固件交互产物：`<rootfs>/<lab_name>/`

