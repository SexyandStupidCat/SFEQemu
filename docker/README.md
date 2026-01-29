# Docker 运行说明（SFEQemu）

目标：用 Docker 提供一致的运行环境，避免在宿主机安装运行期依赖；同时兼容本仓库的 Lua rules + AI（内置类 MCP）流程。

镜像内默认包含：

- `ip`（iproute2）：方便在容器里直接 `ip a` 查看网络信息
- `curl`：用于验证 Web 服务是否可访问

前提：qemu 二进制已在宿主机准备好（自己编译或拷贝现成的）。

## 1) 启动容器（镜像内包含 python3，可用于调用 API）

在仓库根目录执行：

```bash
./docker/start.sh /abs/path/to/rootfs

# 或者使用环境变量：
ROOTFS_DIR=/abs/path/to/rootfs ./docker/start.sh

# 如果你的 Docker 默认 DNS 解析异常，可显式指定网络/DNS（可选）：
# DOCKER_NETWORK=host DOCKER_DNS=223.5.5.5,8.8.8.8 ./docker/start.sh /abs/path/to/rootfs
```

脚本会：

- 构建镜像（只安装运行期依赖 + python3 + ca-certificates）
- 交互式启动容器，并挂载：
  - rootfs -> `/rootfs`
  - 仓库目录 -> 宿主机原始绝对路径（避免 SFAnalysis 输出里的绝对路径失效）
  - 以 root 身份进入容器（便于 `mount_and_chroot.sh` 这类需要特权的脚本）
- 额外把容器内的 `python3`/证书/运行库 **临时 bind mount** 到 `/rootfs`（使 chroot 后也能直接 `python3` 调 API；退出容器会自动清理，不污染宿主机 rootfs）
- 为避免 rootfs 中 `resolv.conf` 常见的“symlink -> /tmp/resolv.conf + /tmp tmpfs”导致 DNS 失效，脚本会优先用 overlayfs 临时覆盖 `/rootfs/etc` 并写入容器的 `resolv.conf`（退出容器自动清理，不污染宿主机 rootfs）

## 2) 在容器内运行（示例命令）

在容器 Shell 里执行你自己的 qemu 命令即可，例如（路径按你的实际情况替换）：

```bash
/abs/path/to/qemu-arm -L . \
  -rules /media/user/ddisk/Work/Project/SFEmu/SFEQemu/rules_examples \
  -shadowstack log=off,summary=on,unwind_limit=100,max_stack=100 \
  -sfanalysis /abs/path/to/SFAnalysis/out_xxx \
  ./usr/sbin/httpd
```

## 3) AI 配置与规则产物位置

- AI 的 key/baseurl/model 等放在：`rules_examples/config/env`（仓库已忽略该文件，避免误提交）。
- AI 生成的临时规则与运行快照在：`rules_examples/cache/ai_runs/<run_id>/`
- 自动导出的“可直接复用的稳定规则”在：`rules_examples/cache/stable_rules/<run_id>/`

## 4) docker-compose（可选）

```bash
cd docker
docker compose run --rm sfemu
```

该方式主要用于进入开发 shell；运行固件建议优先用 `./docker/start.sh`（挂载与工作目录更贴合本仓库的绝对路径约束）。
