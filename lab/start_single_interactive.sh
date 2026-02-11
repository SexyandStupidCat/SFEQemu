#!/usr/bin/env bash
set -euo pipefail

# 单固件交互式启动脚本
#
# 目标：
# 1) 输入 rootfs 目录 + 服务二进制（绝对路径/guest 路径均可）
# 2) 自动执行 SDGen + SFAnalysis（通过 run_batch_001.sh 的单条批处理模式）
# 3) 进入 Docker 交互 shell
# 4) 在容器内执行生成好的启动脚本，按启动序列仿真目标服务

usage() {
  cat <<'EOM'
用法：
  ./lab/start_single_interactive.sh --rootfs <rootfs_abs> --service <service_path>

参数：
  --rootfs <dir>        固件文件系统目录（必须是绝对路径）
  --service <path>      服务二进制路径，支持三种写法：
                        1) rootfs 内绝对路径（如 /usr/sbin/httpd）
                        2) 相对 rootfs 路径（如 usr/sbin/httpd）
                        3) 主机绝对路径（如 /data/fw/rootfs/usr/sbin/httpd）
  --lab-name <name>     产物目录名（默认 sfemu_lab_manual_时间戳）
  --image-tag <tag>     Docker 镜像标签（默认 sfemu-ubuntu2404:local）
  --seq-delay <sec>     前置进程与后置进程分段等待时间（默认 10）
  --force-sdgen         强制重跑 SDGen
  --force-sfanalysis    强制重跑 SFAnalysis
  --skip-sfanalysis     跳过 SFAnalysis（仅做启动序列分析）
  -h, --help            查看帮助

示例：
  ./lab/start_single_interactive.sh \
    --rootfs /media/user/ddisk/Work/FirmAE/firmwares/dataset/dlink/xxx/rootfs \
    --service /usr/sbin/httpd
EOM
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SFEQEMU_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
SFEMU_ROOT="$(cd "${SFEQEMU_ROOT}/.." && pwd -P)"

ROOTFS=""
SERVICE_INPUT=""
LAB_NAME=""
IMAGE_TAG="${IMAGE_TAG:-sfemu-ubuntu2404:local}"
SEQ_DELAY="10"
FORCE_SDGEN_VAL="0"
FORCE_SFANALYSIS_VAL="0"
SKIP_SFANALYSIS_VAL="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rootfs)
      ROOTFS="${2:-}"
      shift 2
      ;;
    --service)
      SERVICE_INPUT="${2:-}"
      shift 2
      ;;
    --lab-name)
      LAB_NAME="${2:-}"
      shift 2
      ;;
    --image-tag)
      IMAGE_TAG="${2:-}"
      shift 2
      ;;
    --seq-delay)
      SEQ_DELAY="${2:-10}"
      shift 2
      ;;
    --force-sdgen)
      FORCE_SDGEN_VAL="1"
      shift
      ;;
    --force-sfanalysis)
      FORCE_SFANALYSIS_VAL="1"
      shift
      ;;
    --skip-sfanalysis)
      SKIP_SFANALYSIS_VAL="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] 未知参数：$1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${ROOTFS}" || -z "${SERVICE_INPUT}" ]]; then
  echo "[ERROR] 必须同时提供 --rootfs 与 --service" >&2
  usage
  exit 1
fi

if [[ ! -d "${ROOTFS}" ]]; then
  echo "[ERROR] rootfs 目录不存在：${ROOTFS}" >&2
  exit 1
fi

ROOTFS_ABS="$(cd "${ROOTFS}" && pwd -P)"

resolve_service_abs() {
  local rootfs_abs="$1"
  local service_input="$2"

  # 1) 主机绝对路径（优先）
  if [[ "${service_input}" == /* && -f "${service_input}" ]]; then
    local p
    p="$(cd "$(dirname "${service_input}")" && pwd -P)/$(basename "${service_input}")"
    echo "${p}"
    return 0
  fi

  # 2) guest 绝对路径（如 /usr/sbin/httpd）
  if [[ "${service_input}" == /* ]]; then
    local p="${rootfs_abs}${service_input}"
    if [[ -f "${p}" ]]; then
      echo "${p}"
      return 0
    fi
  fi

  # 3) 相对 rootfs 路径
  local p="${rootfs_abs}/${service_input#./}"
  if [[ -f "${p}" ]]; then
    p="$(cd "$(dirname "${p}")" && pwd -P)/$(basename "${p}")"
    echo "${p}"
    return 0
  fi

  return 1
}

if ! SERVICE_ABS="$(resolve_service_abs "${ROOTFS_ABS}" "${SERVICE_INPUT}")"; then
  echo "[ERROR] 无法解析服务二进制：${SERVICE_INPUT}" >&2
  exit 1
fi

if [[ "${SERVICE_ABS}" != "${ROOTFS_ABS}"/* ]]; then
  echo "[ERROR] 服务二进制不在 rootfs 内：${SERVICE_ABS}" >&2
  exit 1
fi

SERVICE_GUEST="${SERVICE_ABS#${ROOTFS_ABS}}"
if [[ -z "${SERVICE_GUEST}" || "${SERVICE_GUEST}" == "${SERVICE_ABS}" ]]; then
  echo "[ERROR] 无法推导 guest 路径：${SERVICE_ABS}" >&2
  exit 1
fi

if [[ -z "${LAB_NAME}" ]]; then
  LAB_NAME="sfemu_lab_manual_$(date +%Y%m%d_%H%M%S)"
fi

if [[ ! "${SEQ_DELAY}" =~ ^[0-9]+$ ]]; then
  echo "[ERROR] --seq-delay 必须是非负整数：${SEQ_DELAY}" >&2
  exit 1
fi

log() {
  echo "[single] $*"
}

need_cmd() {
  local c="$1"
  if ! command -v "$c" >/dev/null 2>&1; then
    echo "[single][ERROR] 缺少命令：$c" >&2
    exit 1
  fi
}

need_cmd docker
need_cmd python3

TMP_BATCH="$(mktemp "${SFEQEMU_ROOT}/lab/batch_single_manual.XXXXXX.txt")"
trap 'rm -f "${TMP_BATCH}"' EXIT
printf '%s %s\n' "${SERVICE_ABS}" "${ROOTFS_ABS}" > "${TMP_BATCH}"

log "rootfs: ${ROOTFS_ABS}"
log "service(abs): ${SERVICE_ABS}"
log "service(guest): ${SERVICE_GUEST}"
log "lab: ${LAB_NAME}"

log "步骤 1/3：执行 SDGen + SFAnalysis + 注入（不启动自动仿真）"
(
  cd "${SFEQEMU_ROOT}"
  SEQ_STARTUP=1 \
  FORCE_DOCKER=0 \
  LAB_DIR_NAME="${LAB_NAME}" \
  SEQ_STAGE_DELAY_SECS="${SEQ_DELAY}" \
  FORCE_SDGEN="${FORCE_SDGEN_VAL}" \
  FORCE_SFANALYSIS="${FORCE_SFANALYSIS_VAL}" \
  SKIP_SFANALYSIS="${SKIP_SFANALYSIS_VAL}" \
  ./lab/run_batch_001.sh "${TMP_BATCH}"
)

LAB_DIR="${ROOTFS_ABS}/${LAB_NAME}"
if [[ ! -d "${LAB_DIR}" ]]; then
  echo "[single][ERROR] 产物目录不存在：${LAB_DIR}" >&2
  exit 1
fi

printf '%s\n' "${SERVICE_GUEST}" > "${LAB_DIR}/target.guest.bin"
printf '%s\n' "${ROOTFS_ABS}" > "${LAB_DIR}/target.rootfs.abs"

# 为手工交互场景生成“容器内执行脚本”
cat > "${LAB_DIR}/start_service_seq_in_container.sh" <<EOM
#!/usr/bin/env bash
set -euo pipefail

ROOT="\\${ROOTFS_MOUNT:-/rootfs}"
LAB_DIR="\\${ROOT}/${LAB_NAME}"
TARGET_GUEST="\\$(cat "\\${LAB_DIR}/target.guest.bin" 2>/dev/null || true)"
SEQ_DELAY="\\${SEQ_STAGE_DELAY_SECS:-${SEQ_DELAY}}"
RULES_LOG_LEVEL="\\${RULES_LOG_LEVEL:-error}"
RULES_CTX_KEEP="\\${RULES_CTX_KEEP:-0}"

if [[ ! -d "\\${LAB_DIR}" ]]; then
  echo "[start][ERROR] lab 目录不存在：\\${LAB_DIR}" >&2
  exit 1
fi

is_mounted() {
  grep -qs " \\$1 " /proc/mounts
}

ensure_mounts() {
  mkdir -p "\\${ROOT}/proc" "\\${ROOT}/sys" "\\${ROOT}/dev" "\\${ROOT}/dev/pts" "\\${ROOT}/tmp" || true
  if ! is_mounted "\\${ROOT}/proc"; then mount -t proc proc "\\${ROOT}/proc"; fi
  if ! is_mounted "\\${ROOT}/sys"; then mount -t sysfs sysfs "\\${ROOT}/sys"; fi
  if ! is_mounted "\\${ROOT}/dev"; then mount --bind /dev "\\${ROOT}/dev"; fi
  if ! is_mounted "\\${ROOT}/dev/pts"; then mount --bind /dev/pts "\\${ROOT}/dev/pts"; fi
  if ! is_mounted "\\${ROOT}/tmp"; then mount -t tmpfs tmpfs "\\${ROOT}/tmp"; fi

  mkdir -p "\\${ROOT}/tmp/etc/ssl/certs" || true
  cp -f /etc/resolv.conf "\\${ROOT}/tmp/etc/resolv.conf" 2>/dev/null || true
  cp -f /etc/hosts "\\${ROOT}/tmp/etc/hosts" 2>/dev/null || true
  cp -f /etc/nsswitch.conf "\\${ROOT}/tmp/etc/nsswitch.conf" 2>/dev/null || true
  cp -f /etc/ssl/certs/ca-certificates.crt "\\${ROOT}/tmp/etc/ssl/certs/ca-certificates.crt" 2>/dev/null || true
}

pick_webroot_host() {
  local cands=("/htdocs" "/www" "/web" "/var/www/html" "/var/www" "/home/httpd")
  local p
  for p in "\\${cands[@]}"; do
    if [[ -d "\\${ROOT}\\${p}" ]]; then
      echo "\\${ROOT}\\${p}"
      return 0
    fi
  done
  echo "\\${ROOT}"
}

load_startup_bins() {
  local list=""
  if [[ -s "\\${LAB_DIR}/startup_list.effective.txt" ]]; then
    list="\\${LAB_DIR}/startup_list.effective.txt"
  elif [[ -s "\\${LAB_DIR}/startup_binaries.guest.txt" ]]; then
    list="\\${LAB_DIR}/startup_binaries.guest.txt"
  fi

  if [[ -n "\\${list}" ]]; then
    mapfile -t seq_bins < <(awk '!/^[[:space:]]*(#|$)/ {print \\$1}' "\\${list}")
  else
    seq_bins=()
  fi

  if [[ "\\${#seq_bins[@]}" -eq 0 && -n "\\${TARGET_GUEST}" ]]; then
    seq_bins=("\\${TARGET_GUEST}")
  fi
}

prepend_dlink_prereqs() {
  local has_httpd=0
  local has_goahead=0
  local b
  for b in "\\${seq_bins[@]}"; do
    [[ "\\${b##*/}" == "httpd" ]] && has_httpd=1
    [[ "\\${b##*/}" == "goahead" ]] && has_goahead=1
  done

  # D-Link: 若存在模板，优先补 xmldb/xmldbc
  if [[ "\\${has_httpd}" == "1" && -f "\\${ROOT}/etc/services/HTTP/httpcfg.php" ]]; then
    local xdb=""
    for p in /usr/sbin/xmldb /usr/sbin/xmldbc /usr/bin/xmldb /usr/bin/xmldbc /sbin/xmldb /sbin/xmldbc /bin/xmldb /bin/xmldbc; do
      if [[ -x "\\${ROOT}\\${p}" ]]; then
        xdb="\\${p}"
        break
      fi
    done
    if [[ -n "\\${xdb}" ]]; then
      local exist=0
      for b in "\\${seq_bins[@]}"; do
        [[ "\\${b}" == "\\${xdb}" ]] && exist=1
      done
      if [[ "\\${exist}" == "0" ]]; then
        seq_bins=("\\${xdb}" "\\${seq_bins[@]}")
      fi
    fi
  fi

  # D-Link/goahead: 尝试补 nvram_daemon
  if [[ "\\${has_goahead}" == "1" ]]; then
    local nvramd=""
    for p in /bin/nvram_daemon /sbin/nvram_daemon /usr/sbin/nvram_daemon /usr/bin/nvram_daemon; do
      if [[ -x "\\${ROOT}\\${p}" ]]; then
        nvramd="\\${p}"
        break
      fi
    done
    if [[ -n "\\${nvramd}" ]]; then
      local exist=0
      for b in "\\${seq_bins[@]}"; do
        [[ "\\${b}" == "\\${nvramd}" ]] && exist=1
      done
      if [[ "\\${exist}" == "0" ]]; then
        seq_bins=("\\${nvramd}" "\\${seq_bins[@]}")
      fi
      mkdir -p "\\${ROOT}/var/run" 2>/dev/null || true
      [[ -e "\\${ROOT}/var/run/nvramd.pid" ]] || echo 1 > "\\${ROOT}/var/run/nvramd.pid"
    fi
  fi

  printf '%s\n' "\\${seq_bins[@]}" > "\\${LAB_DIR}/startup_list.manual.effective.txt"
}

pick_qemu() {
  local qname
  qname="\\$(cat "\\${LAB_DIR}/qemu.bin" 2>/dev/null || true)"
  if [[ -n "\\${qname}" && -x "\\${ROOT}/\\${qname}" ]]; then
    echo "\\${ROOT}/\\${qname}"
    return 0
  fi

  if [[ -n "\\${TARGET_GUEST}" && -e "\\${ROOT}\\${TARGET_GUEST}" ]]; then
    local f
    f="\\$(file -bL "\\${ROOT}\\${TARGET_GUEST}" 2>/dev/null || true)"
    if [[ "\\${f}" == *"ARM"* && -x "\\${ROOT}/qemu-arm" ]]; then echo "\\${ROOT}/qemu-arm"; return 0; fi
    if [[ "\\${f}" == *"MIPS"* && "\\${f}" == *"LSB"* && -x "\\${ROOT}/qemu-mipsel" ]]; then echo "\\${ROOT}/qemu-mipsel"; return 0; fi
    if [[ "\\${f}" == *"MIPS"* && "\\${f}" == *"MSB"* && -x "\\${ROOT}/qemu-mips" ]]; then echo "\\${ROOT}/qemu-mips"; return 0; fi
  fi

  for q in "\\${ROOT}/qemu-arm" "\\${ROOT}/qemu-mipsel" "\\${ROOT}/qemu-mips"; do
    if [[ -x "\\${q}" ]]; then
      echo "\\${q}"
      return 0
    fi
  done

  return 1
}

load_args_for_bin() {
  local guest_bin="\\$1"
  local args_json=""
  if [[ -s "\\${LAB_DIR}/startup_args.effective.guest.json" ]]; then
    args_json="\\${LAB_DIR}/startup_args.effective.guest.json"
  elif [[ -s "\\${LAB_DIR}/startup_args.guest.json" ]]; then
    args_json="\\${LAB_DIR}/startup_args.guest.json"
  fi

  if [[ -z "\\${args_json}" ]]; then
    return 0
  fi

  python3 - "\\${args_json}" "\\${guest_bin}" <<'PY'
import json
import os
import sys

args_json = sys.argv[1]
guest_bin = sys.argv[2]

if not os.path.isfile(args_json):
    raise SystemExit(0)

try:
    data = json.load(open(args_json, "r", encoding="utf-8"))
except Exception:
    raise SystemExit(0)

value = data.get(guest_bin)
out = []

if isinstance(value, list):
    out = [str(x) for x in value]
elif isinstance(value, dict):
    argv = value.get("argv")
    args = value.get("args")
    if isinstance(args, list):
        out = [str(x) for x in args]
    elif isinstance(argv, list):
        out = [str(x) for x in argv]
        if out and out[0] == guest_bin:
            out = out[1:]

for item in out:
    print(item)
PY
}

start_one() {
  local qemu_bin="\\$1"
  local guest_bin="\\$2"
  local idx="\\$3"
  local log_dir="\\$4"
  local sfanalysis_opt="\\$5"

  if [[ ! -e "\\${ROOT}\\${guest_bin}" ]]; then
    echo "[start][seq] skip(notfound): \\${guest_bin}" | tee -a "\\${log_dir}/seq_run.log"
    return 0
  fi

  local -a cmd
  cmd=("\\${qemu_bin}" -L "\\${ROOT}" -rules "\\${ROOT}/rules_examples/" -rules-log-level "\\${RULES_LOG_LEVEL}" -rules-ctx-keep "\\${RULES_CTX_KEEP}" -rules-idle-ms 1000)

  if [[ -n "\\${sfanalysis_opt}" ]]; then
    cmd+=( -sfanalysis "\\${sfanalysis_opt}" )
  fi

  cmd+=( "\\${ROOT}\\${guest_bin}" )

  local -a guest_args
  mapfile -t guest_args < <(load_args_for_bin "\\${guest_bin}")
  if [[ "\\${#guest_args[@]}" -gt 0 ]]; then
    cmd+=("\\${guest_args[@]}")
  fi

  echo "[start][seq] idx=\\${idx} cmd=\\${cmd[*]}" | tee -a "\\${log_dir}/seq_run.log"
  "\\${cmd[@]}" > "\\${log_dir}/\\${idx}_stdout.log" 2> "\\${log_dir}/\\${idx}_stderr.log" &
  local pid=\\$!
  echo "\\${pid}" > "\\${log_dir}/\\${idx}.pid"
}

main() {
  ensure_mounts

  load_startup_bins
  if [[ "\\${#seq_bins[@]}" -eq 0 ]]; then
    echo "[start][ERROR] 启动序列为空，且没有目标服务可回退。" >&2
    exit 1
  fi

  prepend_dlink_prereqs

  local qemu_bin
  if ! qemu_bin="\\$(pick_qemu)"; then
    echo "[start][ERROR] 无法确定 qemu-user（二进制不存在）。" >&2
    exit 1
  fi

  local sfanalysis_opt=""
  if compgen -G "\\${ROOT}/out_httpd/*.json" >/dev/null 2>&1; then
    sfanalysis_opt="\\${ROOT}/out_httpd"
  fi

  local log_dir="\\${LAB_DIR}/seq_manual"
  mkdir -p "\\${log_dir}"

  local webroot
  webroot="\\$(pick_webroot_host)"
  cd "\\${webroot}" 2>/dev/null || cd "\\${ROOT}"

  local seq_cnt="\\${#seq_bins[@]}"
  local idx=0

  if (( seq_cnt > 1 && SEQ_DELAY > 0 )); then
    for ((i=0; i<seq_cnt-1; i++)); do
      idx=\\$((idx+1))
      start_one "\\${qemu_bin}" "\\${seq_bins[\\${i}]}" "\\${idx}" "\\${log_dir}" "\\${sfanalysis_opt}"
    done

    echo "[start][seq] 前置进程已启动，等待 \\${SEQ_DELAY}s 后拉起后置进程" | tee -a "\\${log_dir}/seq_run.log"
    sleep "\\${SEQ_DELAY}"

    idx=\\$((idx+1))
    start_one "\\${qemu_bin}" "\\${seq_bins[\\$((seq_cnt-1))]}" "\\${idx}" "\\${log_dir}" "\\${sfanalysis_opt}"
  else
    for b in "\\${seq_bins[@]}"; do
      idx=\\$((idx+1))
      start_one "\\${qemu_bin}" "\\${b}" "\\${idx}" "\\${log_dir}" "\\${sfanalysis_opt}"
    done
  fi

  echo "[start] 启动完成。可用以下命令检查："
  echo "        ss -lntp | grep -E '(:80|:443|:8080|qemu-)'
"
  echo "        curl -v http://127.0.0.1/"
  echo "[start] 日志目录：\\${log_dir}"
}

main "\\$@"
EOM
chmod +x "${LAB_DIR}/start_service_seq_in_container.sh"

cat > "${LAB_DIR}/README.manual_start.txt" <<EOM
[SFEmu 单固件交互说明]

1) 先在容器 shell 内执行：
   /rootfs/${LAB_NAME}/start_service_seq_in_container.sh

2) 启动后验证：
   ss -lntp | grep -E '(:80|:443|:8080|qemu-)'
   curl -v http://127.0.0.1/

3) 日志位置：
   /rootfs/${LAB_NAME}/seq_manual/
EOM

log "步骤 2/3：确保运行镜像可用（${IMAGE_TAG}）"
if ! docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
  log "镜像不存在，自动构建 ${IMAGE_TAG}"
  docker build -t "${IMAGE_TAG}" -f "${SFEMU_ROOT}/workspace/Dockerfile" "${SFEMU_ROOT}/workspace"
fi

log "步骤 3/3：进入交互式 Docker shell"
log "进入后执行：/rootfs/${LAB_NAME}/start_service_seq_in_container.sh"

# 注意：rootfs 路径可能含空格，必须使用数组传参。
docker_args=(
  docker run --rm -it --privileged
  -e TERM
  -v "${ROOTFS_ABS}:/rootfs:rw"
  -v "${SFEMU_ROOT}:${SFEMU_ROOT}:rw"
  -w /rootfs
  "${IMAGE_TAG}"
  /bin/bash -lc
)

"${docker_args[@]}" "
  set -euo pipefail
  echo '[container] 已进入容器。'
  echo '[container] 目标 rootfs: /rootfs'
  echo '[container] 启动脚本: /rootfs/${LAB_NAME}/start_service_seq_in_container.sh'
  echo '[container] 产物目录: /rootfs/${LAB_NAME}'
  echo
  exec /bin/bash
"
