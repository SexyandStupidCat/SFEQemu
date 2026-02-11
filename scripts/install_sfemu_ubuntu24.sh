#!/usr/bin/env bash
set -euo pipefail

# SFEmu 一键安装脚本（Ubuntu 24.04）
#
# 作用：
# 1) 安装静态分析/动态仿真依赖（Docker、Java、Python、QEMU 构建依赖）
# 2) 安装 Python 依赖（pyghidra/jpype1/loguru）
# 3) 构建 SFEQemu 的 qemu-arm/qemu-mips/qemu-mipsel 并复制到 workspace/rootfs
# 4) 构建动态仿真 Docker 镜像（sfemu-ubuntu2404:local）
#
# 用法：
#   ./scripts/install_sfemu_ubuntu24.sh
#
# 可选环境变量：
#   SKIP_APT=1                 # 跳过 apt 安装
#   SKIP_PYTHON=1              # 跳过 venv/pip 安装
#   SKIP_QEMU_BUILD=1          # 跳过 qemu-user 构建
#   SKIP_DOCKER_IMAGE=1        # 跳过 Docker 镜像构建
#   PY_VENV_PATH=/abs/venv     # 指定 Python 虚拟环境路径
#   GHIDRA_ROOT=/abs/ghidra    # 指定 Ghidra 目录（用于 SDGen/SFAnalysis）
#   GHIDRA_ZIP_URL=...         # 可选：若未安装 Ghidra，自动下载并解压

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SFEQEMU_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
SFEMU_ROOT="$(cd "${SFEQEMU_ROOT}/.." && pwd -P)"
WORKSPACE_ROOT="${SFEMU_ROOT}/workspace"

SKIP_APT="${SKIP_APT:-0}"
SKIP_PYTHON="${SKIP_PYTHON:-0}"
SKIP_QEMU_BUILD="${SKIP_QEMU_BUILD:-0}"
SKIP_DOCKER_IMAGE="${SKIP_DOCKER_IMAGE:-0}"
IMAGE_TAG="${IMAGE_TAG:-sfemu-ubuntu2404:local}"
PY_VENV_PATH="${PY_VENV_PATH:-${SFEMU_ROOT}/.venv-sfemu}"
GHIDRA_ZIP_URL="${GHIDRA_ZIP_URL:-}"

log() {
  echo "[install] $*"
}

warn() {
  echo "[install][WARN] $*" >&2
}

need_cmd() {
  local c="$1"
  if ! command -v "$c" >/dev/null 2>&1; then
    echo "[install][ERROR] 缺少命令：$c" >&2
    exit 1
  fi
}

ensure_apt_packages() {
  if [[ "${SKIP_APT}" == "1" ]]; then
    log "SKIP_APT=1，跳过 apt 依赖安装"
    return 0
  fi

  need_cmd sudo
  need_cmd apt-get

  log "更新 apt 索引"
  sudo apt-get update

  log "安装系统依赖（Ubuntu 24.04）"
  sudo apt-get install -y \
    bash \
    build-essential \
    ca-certificates \
    curl \
    docker.io \
    file \
    git \
    iproute2 \
    jq \
    libcapstone-dev \
    libfdt-dev \
    libglib2.0-dev \
    libpixman-1-dev \
    libslirp-dev \
    meson \
    ninja-build \
    openjdk-17-jdk-headless \
    pkg-config \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    rsync \
    unzip \
    wget \
    zlib1g-dev

  log "启用并启动 Docker 服务"
  sudo systemctl enable --now docker

  if ! groups "${USER}" | grep -q '\bdocker\b'; then
    log "将当前用户加入 docker 组（重新登录后生效）"
    sudo usermod -aG docker "${USER}"
    warn "已加入 docker 组。请在安装完成后重新登录一次，以免后续执行 docker 需要 sudo。"
  fi
}

find_ghidra_root() {
  if [[ -n "${GHIDRA_ROOT:-}" && -x "${GHIDRA_ROOT}/support/analyzeHeadless" ]]; then
    echo "${GHIDRA_ROOT}"
    return 0
  fi

  local candidates=(
    "${HOME}/Applications/ghidra"
    "${HOME}/Applications/ghidra_11.2.1_PUBLIC"
    "${HOME}/.local/opt/ghidra"
    "${HOME}/.local/opt/ghidra_11.2.1_PUBLIC"
    "/opt/ghidra"
  )

  local c
  for c in "${candidates[@]}"; do
    if [[ -x "${c}/support/analyzeHeadless" ]]; then
      echo "${c}"
      return 0
    fi
  done

  echo ""
  return 0
}

install_ghidra_if_needed() {
  local ghidra_root
  ghidra_root="$(find_ghidra_root)"
  if [[ -n "${ghidra_root}" ]]; then
    log "检测到 Ghidra：${ghidra_root}"
    export GHIDRA_ROOT="${ghidra_root}"
    return 0
  fi

  if [[ -z "${GHIDRA_ZIP_URL}" ]]; then
    warn "未检测到 Ghidra，且未提供 GHIDRA_ZIP_URL。"
    warn "SDGen/SFAnalysis 需要 Ghidra；请手工安装后设置 GHIDRA_ROOT。"
    return 0
  fi

  need_cmd wget
  need_cmd unzip

  local install_base="${HOME}/.local/opt"
  local zip_path="${install_base}/ghidra_download.zip"
  mkdir -p "${install_base}"

  log "下载 Ghidra：${GHIDRA_ZIP_URL}"
  wget -O "${zip_path}" "${GHIDRA_ZIP_URL}"

  log "解压 Ghidra 到：${install_base}"
  unzip -o "${zip_path}" -d "${install_base}"

  ghidra_root="$(find "${install_base}" -maxdepth 2 -type f -name analyzeHeadless 2>/dev/null | head -n 1 | xargs -r dirname | xargs -r dirname || true)"
  if [[ -n "${ghidra_root}" && -x "${ghidra_root}/support/analyzeHeadless" ]]; then
    export GHIDRA_ROOT="${ghidra_root}"
    log "Ghidra 安装完成：${GHIDRA_ROOT}"
  else
    warn "自动安装 Ghidra 失败，请手工安装并设置 GHIDRA_ROOT。"
  fi
}

setup_python_env() {
  if [[ "${SKIP_PYTHON}" == "1" ]]; then
    log "SKIP_PYTHON=1，跳过 Python 依赖安装"
    return 0
  fi

  need_cmd python3

  log "创建 Python 虚拟环境：${PY_VENV_PATH}"
  python3 -m venv "${PY_VENV_PATH}"

  # shellcheck disable=SC1091
  source "${PY_VENV_PATH}/bin/activate"

  log "升级 pip/setuptools/wheel"
  pip install --upgrade pip setuptools wheel

  log "安装 Python 依赖：pyghidra/jpype1/loguru"
  pip install --upgrade pyghidra jpype1 loguru

  deactivate || true
}

build_qemu_user_static() {
  if [[ "${SKIP_QEMU_BUILD}" == "1" ]]; then
    log "SKIP_QEMU_BUILD=1，跳过 qemu-user 构建"
    return 0
  fi

  need_cmd make

  local build_dir="${SFEQEMU_ROOT}/build-user-static"
  mkdir -p "${build_dir}"

  pushd "${build_dir}" >/dev/null

  if [[ ! -f "config-host.mak" ]]; then
    log "配置 qemu-user-static（arm/mips/mipsel）"
    ../configure \
      --target-list=arm-linux-user,mips-linux-user,mipsel-linux-user \
      --static
  fi

  log "编译 qemu-user-static（这一步耗时较长）"
  make -j"$(nproc)" qemu-arm qemu-mips qemu-mipsel

  popd >/dev/null

  mkdir -p "${WORKSPACE_ROOT}/rootfs"
  install -m 0755 "${build_dir}/qemu-arm" "${WORKSPACE_ROOT}/rootfs/qemu-arm"
  install -m 0755 "${build_dir}/qemu-mips" "${WORKSPACE_ROOT}/rootfs/qemu-mips"
  install -m 0755 "${build_dir}/qemu-mipsel" "${WORKSPACE_ROOT}/rootfs/qemu-mipsel"

  log "已复制 qemu-user 到 ${WORKSPACE_ROOT}/rootfs"
}

build_runtime_image() {
  if [[ "${SKIP_DOCKER_IMAGE}" == "1" ]]; then
    log "SKIP_DOCKER_IMAGE=1，跳过 Docker 镜像构建"
    return 0
  fi

  need_cmd docker

  local dockerfile="${WORKSPACE_ROOT}/Dockerfile"
  if [[ ! -f "${dockerfile}" ]]; then
    warn "未找到 Dockerfile：${dockerfile}，跳过镜像构建"
    return 0
  fi

  log "构建运行镜像：${IMAGE_TAG}"
  docker build -t "${IMAGE_TAG}" -f "${dockerfile}" "${WORKSPACE_ROOT}"
}

print_summary() {
  local ghidra_root
  ghidra_root="$(find_ghidra_root)"

  cat <<EOM

================ 安装完成 ================
SFEQemu: ${SFEQEMU_ROOT}
SFEmu:   ${SFEMU_ROOT}
venv:    ${PY_VENV_PATH}
Ghidra:  ${ghidra_root:-<未检测到>}
镜像:    ${IMAGE_TAG}

建议后续执行：
1) 重新登录（若刚加入 docker 组）
2) 启用 Python 环境：
   source "${PY_VENV_PATH}/bin/activate"
3) 若未检测到 Ghidra，请手工设置：
   export GHIDRA_ROOT=/path/to/ghidra

快速验证：
- qemu-arm -h（确认 qemu-user 已安装）
- docker image inspect ${IMAGE_TAG}
- python3 -c 'import pyghidra, jpype, loguru; print("python deps ok")'
=========================================

EOM
}

main() {
  log "仓库根目录：${SFEQEMU_ROOT}"
  log "SFEmu 根目录：${SFEMU_ROOT}"

  ensure_apt_packages
  install_ghidra_if_needed
  setup_python_env
  build_qemu_user_static
  build_runtime_image
  print_summary
}

main "$@"
