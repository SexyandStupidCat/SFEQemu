#!/usr/bin/env bash
set -euo pipefail

# 轻量启动脚本：在原有基础上仅补齐“能跑 API”的运行环境（镜像内装 python3 + ca-certificates）。
# - qemu 请在宿主机自行编译好并放到 rootfs 或仓库目录中
# - 容器会把「仓库目录」按原始绝对路径挂载进去，避免 SFAnalysis 等产物里的绝对路径失效

IMAGE_TAG="${IMAGE_TAG:-sfemu-ubuntu2404:local}"
DOCKER_NETWORK="${DOCKER_NETWORK:-}"
DOCKER_DNS="${DOCKER_DNS:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

# rootfs 目录：优先取第一个参数，其次 ROOTFS_DIR 环境变量，最后回退到 docker/rootfs（兼容原脚本）
ROOTFS_DIR="${1:-${ROOTFS_DIR:-${SCRIPT_DIR}/rootfs}}"
if [[ ! -d "${ROOTFS_DIR}" ]]; then
  echo "未找到 rootfs 目录：${ROOTFS_DIR}" >&2
  echo "用法示例：" >&2
  echo "  ROOTFS_DIR=/abs/path/to/rootfs ./docker/start.sh" >&2
  echo "  ./docker/start.sh /abs/path/to/rootfs" >&2
  exit 1
fi

# 构建镜像（只安装运行期依赖 + python3，用于 rules_examples/tools/ai_mcp_openai.py 调用 API）
docker build -t "${IMAGE_TAG}" -f "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}"

# 可选：自定义 Docker 网络/DNS（某些环境下 Docker 默认 DNS 不可用时）
DOCKER_RUN_EXTRA=()
if [[ -n "${DOCKER_NETWORK}" ]]; then
  DOCKER_RUN_EXTRA+=(--network "${DOCKER_NETWORK}")
fi
if [[ -n "${DOCKER_DNS}" ]]; then
  IFS=',' read -r -a _dns_list <<< "${DOCKER_DNS}"
  for _dns in "${_dns_list[@]}"; do
    _dns="${_dns//[[:space:]]/}"
    if [[ -n "${_dns}" ]]; then
      DOCKER_RUN_EXTRA+=(--dns "${_dns}")
    fi
  done
fi

# 以交互模式进入 Ubuntu 24.04，并映射：
# - rootfs -> /rootfs
# - repo   -> 原始绝对路径（便于访问 rules_examples/ 与 SFAnalysis 输出中的绝对路径）
exec docker run --rm -it \
  --privileged \
  -e TERM \
  "${DOCKER_RUN_EXTRA[@]}" \
  -v "${ROOTFS_DIR}:/rootfs:rw" \
  -v "${REPO_ROOT}:${REPO_ROOT}:rw" \
  -w /rootfs \
  "${IMAGE_TAG}" \
  /bin/bash -lc "
    set -euo pipefail

    # 让 chroot(rootfs) 内也能直接执行 python3（用于 AI MCP 调 API）：
    # - 将容器内 x86_64 的 python3 + 运行库 + 证书，bind mount 到 /rootfs 对应路径
    # - 不写入宿主机 rootfs（仅影响容器的 mount namespace）
    is_mounted() { grep -qs \" \$1 \" /proc/mounts; }

    created_files=()
    created_dirs=()
    mounted_targets=()
    overlay_upper=""
    overlay_work=""
    overlay_ok=0

    bind_mount() {
      local src=\"\$1\" dst=\"\$2\"
      [[ -e \"\$src\" ]] || return 0
      if is_mounted \"\$dst\"; then
        return 0
      fi
      if [[ ! -d \"\$dst\" ]]; then
        if [[ -e \"\$dst\" ]]; then
          return 0
        fi
        created_dirs+=(\"\$dst\")
        mkdir -p \"\$dst\"
      fi
      mount --bind \"\$src\" \"\$dst\"
      mounted_targets+=(\"\$dst\")
    }

    bind_mount_file() {
      local src=\"\$1\" dst=\"\$2\"
      [[ -e \"\$src\" ]] || return 0
      if is_mounted \"\$dst\"; then
        return 0
      fi
      if [[ ! -e \"\$dst\" ]]; then
        created_files+=(\"\$dst\")
        mkdir -p \"\$(dirname \"\$dst\")\"
        : >\"\$dst\"
      fi
      mount --bind \"\$src\" \"\$dst\"
      mounted_targets+=(\"\$dst\")
    }

    cleanup() {
      set +e
      # 先卸载更深层挂载点（逆序），避免父挂载点 busy
      for ((i=\${#mounted_targets[@]}-1; i>=0; i--)); do
        local t=\"\${mounted_targets[\$i]}\"
        if is_mounted \"\$t\"; then
          umount -l \"\$t\" >/dev/null 2>&1 || true
        fi
      done
      for f in \"\${created_files[@]}\"; do
        rm -f -- \"\$f\" >/dev/null 2>&1 || true
      done
      # 尽量清理我们创建的挂载点目录（只删除空目录）
      for ((i=\${#created_dirs[@]}-1; i>=0; i--)); do
        rmdir -- \"\${created_dirs[\$i]}\" >/dev/null 2>&1 || true
      done
      if [[ -n \"\$overlay_upper\" ]]; then
        rm -rf -- \"\$overlay_upper\" >/dev/null 2>&1 || true
      fi
      if [[ -n \"\$overlay_work\" ]]; then
        rm -rf -- \"\$overlay_work\" >/dev/null 2>&1 || true
      fi
    }
    trap cleanup EXIT

    # 关键点：rootfs 的 /etc/resolv.conf 常见是 symlink -> /tmp/resolv.conf；
    # 而 chroot 脚本通常会把 /tmp 挂载成 tmpfs，导致 DNS 失效。
    # 这里用 overlayfs 给 /rootfs/etc 做一个“临时可写覆盖层”，然后把容器的 resolv.conf 写进去，
    # 从而避免修改宿主机 rootfs，同时保证 chroot 后 DNS 始终可用。
    if [[ -d /rootfs/etc ]]; then
      overlay_upper=/tmp/sfemu_etc_upper
      overlay_work=/tmp/sfemu_etc_work
      mkdir -p \"\$overlay_upper\" \"\$overlay_work\"
      if mount -t overlay overlay -o lowerdir=/rootfs/etc,upperdir=\"\$overlay_upper\",workdir=\"\$overlay_work\" /rootfs/etc 2>/dev/null; then
        overlay_ok=1
        mounted_targets+=(/rootfs/etc)
      else
        rm -rf -- \"\$overlay_upper\" \"\$overlay_work\" >/dev/null 2>&1 || true
        overlay_upper=\"\"
        overlay_work=\"\"
      fi
    fi

    bind_mount_file /usr/bin/python3 /rootfs/usr/bin/python3
    bind_mount /usr/lib/python3 /rootfs/usr/lib/python3
    bind_mount /usr/lib/python3.12 /rootfs/usr/lib/python3.12
    bind_mount /usr/lib/x86_64-linux-gnu /rootfs/usr/lib/x86_64-linux-gnu
    bind_mount /lib/x86_64-linux-gnu /rootfs/lib/x86_64-linux-gnu
    bind_mount_file /lib64/ld-linux-x86-64.so.2 /rootfs/lib64/ld-linux-x86-64.so.2
    bind_mount /etc/ssl/certs /rootfs/etc/ssl/certs
    # DNS/主机名解析：让 chroot 内的 python3 能正常解析域名
    if [[ \"\$overlay_ok\" == \"1\" ]]; then
      cp -f /etc/resolv.conf /rootfs/etc/resolv.conf 2>/dev/null || true
      cp -f /etc/nsswitch.conf /rootfs/etc/nsswitch.conf 2>/dev/null || true
      cp -f /etc/hosts /rootfs/etc/hosts 2>/dev/null || true
    else
      # overlayfs 不可用时退化为 bind mount（可能受 /tmp tmpfs + symlink 影响）
      bind_mount_file /etc/resolv.conf /rootfs/etc/resolv.conf
      bind_mount_file /etc/nsswitch.conf /rootfs/etc/nsswitch.conf
      bind_mount_file /etc/hosts /rootfs/etc/hosts
    fi

    if [[ \"\$overlay_ok\" == \"1\" ]]; then
      echo \"[docker] overlayfs 已启用：/rootfs/etc（chroot DNS 更稳）\"
    else
      echo \"[docker] overlayfs 未启用：使用 bind mount 注入 DNS 文件（若 rootfs 的 resolv.conf 是 /tmp symlink，可能仍受 /tmp tmpfs 影响）\"
    fi
    echo \"[docker] 已注入 python3/证书到 /rootfs（chroot 内可直接用 python3 调 API）\"
    /bin/bash
  "
