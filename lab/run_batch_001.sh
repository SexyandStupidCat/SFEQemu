#!/usr/bin/env bash
set -euo pipefail

# 批量实验脚本（批次 001）
#
# 功能：
# 1) SDGen：生成依赖图/启动序列（sdg.json）
# 2) SFAnalysis：生成静态分析结果（out_httpd/，含伪C）
# 3) 注入：qemu-arm、mount_and_chroot.sh、rules_examples、start.sh、env
# 4) Docker：启动仿真并用 curl 验证（有回包即成功）
#
# 用法：
#   ./lab/run_batch_001.sh [batch_file]

BATCH_FILE="${1:-lab/batch_001_asus_arm_httpd.txt}"

SFEQEMU_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SFEMU_ROOT="$(cd "${SFEQEMU_ROOT}/.." && pwd -P)" # /media/.../SFEmu

WORKSPACE_ROOT="${SFEMU_ROOT}/workspace"
SDGEN_ROOT="${SFEMU_ROOT}/SDGen"
SFANALYSIS_ROOT="${SFEMU_ROOT}/SFAnalysis"

IMAGE_TAG="${IMAGE_TAG:-sfemu-ubuntu2404:local}"
QEMU_ARM_SRC="${WORKSPACE_ROOT}/rootfs/qemu-arm"
MOUNT_SRC="${WORKSPACE_ROOT}/rootfs/mount_and_chroot.sh"
RULES_SRC="${SFEQEMU_ROOT}/rules_examples"
FORCE_SDGEN="${FORCE_SDGEN:-0}"
FORCE_SFANALYSIS="${FORCE_SFANALYSIS:-0}"
FORCE_DOCKER="${FORCE_DOCKER:-1}"

if [[ ! -f "${BATCH_FILE}" ]]; then
  echo "[!] batch 文件不存在：${BATCH_FILE}" >&2
  exit 1
fi
if [[ ! -x "${QEMU_ARM_SRC}" ]]; then
  echo "[!] qemu-arm 不存在/不可执行：${QEMU_ARM_SRC}" >&2
  exit 1
fi
if [[ ! -f "${MOUNT_SRC}" ]]; then
  echo "[!] mount_and_chroot.sh 不存在：${MOUNT_SRC}" >&2
  exit 1
fi
if [[ ! -d "${RULES_SRC}" ]]; then
  echo "[!] rules_examples 不存在：${RULES_SRC}" >&2
  exit 1
fi

echo "[*] 使用 batch：${BATCH_FILE}"
echo "[*] Docker image：${IMAGE_TAG}"

if ! docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
  echo "[+] 构建 Docker 镜像：${IMAGE_TAG}"
  docker build -t "${IMAGE_TAG}" -f "${WORKSPACE_ROOT}/Dockerfile" "${WORKSPACE_ROOT}"
fi

run_one() {
  local httpd_abs="$1"
  local rootfs="$2"

  local fw_name
  fw_name="$(basename "$(dirname "${rootfs}")")"

  local lab_dir="${rootfs}/sfemu_lab"
  mkdir -p "${lab_dir}"

  echo "========== ${fw_name} =========="
  echo "[*] httpd: ${httpd_abs}"
  echo "[*] rootfs: ${rootfs}"

  # ---- 注入：qemu-arm / mount 脚本 / rules_examples ----
  install -m 0755 "${QEMU_ARM_SRC}" "${rootfs}/qemu-arm"
  install -m 0755 "${MOUNT_SRC}" "${rootfs}/mount_and_chroot.sh"

  if command -v rsync >/dev/null 2>&1; then
    rsync -a "${RULES_SRC}/" "${rootfs}/rules_examples/"
  else
    mkdir -p "${rootfs}/rules_examples"
    cp -a "${RULES_SRC}/." "${rootfs}/rules_examples/"
  fi
  mkdir -p "${rootfs}/rules_examples/syscall_override_user"
  mkdir -p "${rootfs}/rules_examples/config"

  # env：无人值守（避免卡住等待 YES），且默认不启用外部 AI（需要时可手工打开）
  cat >"${rootfs}/rules_examples/config/env" <<'EOF'
# 自动注入：批量仿真默认配置（可按固件覆盖）
SFEMU_AI_ENABLE=0
SFEMU_AI_MCP_ENABLE=0
SFEMU_AI_AUTO_CONTINUE=1
SFEMU_AI_APPLY_RULES=1
SFEMU_AI_APPLY_OBSERVE=0
SFEMU_AI_OVERWRITE_RULES=0
SFEMU_AI_VERIFY_SYSCALLS=2048
SFEMU_AI_DISABLE_AFTER_STABLE=1
# 仅启用人工 override（每固件特有规则），避免历史遗留的 AI override 干扰通用基线规则
SFEMU_RULES_OVERRIDE_DIR=syscall_override_user
SFEMU_LOG_RULE_LOAD=0
auto_ai=1
EOF

  # ---- SDGen：依赖图/启动序列 ----
  if [[ "${FORCE_SDGEN}" == "1" || ! -s "${lab_dir}/sdg.json" ]]; then
    echo "[+] SDGen..."
    (
      cd "${SDGEN_ROOT}"
      python3 find_need.py "${httpd_abs}" "${rootfs}" "${lab_dir}/sdg.json" 10 --min-confidence=0.8
    ) >"${lab_dir}/sdgen.stdout.log" 2>"${lab_dir}/sdgen.stderr.log" || true
  else
    echo "[=] SDGen: 已存在 ${lab_dir}/sdg.json，跳过（FORCE_SDGEN=1 可强制）"
  fi

  # ---- SFAnalysis：静态分析（伪C）----
  if [[ "${FORCE_SFANALYSIS}" == "1" || -z "$(find "${rootfs}/out_httpd" -maxdepth 1 -name '*.json' -print -quit 2>/dev/null)" ]]; then
    echo "[+] SFAnalysis..."
    (
      cd "${SFANALYSIS_ROOT}"
      python3 pyghidra_fw_analyze.py --binary "${httpd_abs}" --fs-root "${rootfs}" --out-dir "${rootfs}/out_httpd" --emit-pseudocode
    ) >"${lab_dir}/sfanalysis.stdout.log" 2>"${lab_dir}/sfanalysis.stderr.log" || true
  else
    echo "[=] SFAnalysis: 已存在 ${rootfs}/out_httpd/*.json，跳过（FORCE_SFANALYSIS=1 可强制）"
  fi

  # ---- start.sh：固件内启动 httpd（qemu-user + rules + sfanalysis）----
  local httpd_in_guest="${httpd_abs#${rootfs}}"
  if [[ "${httpd_in_guest}" == "${httpd_abs}" ]]; then
    # 兜底：如果无法直接剥离 rootfs 前缀，则回退用常见路径
    httpd_in_guest="/usr/sbin/httpd"
  fi

  cat >"${rootfs}/start.sh" <<EOF
#!/bin/sh
set -eu

SCRIPT_DIR="\$(cd "\$(dirname "\$0")" && pwd)"

OUT_DIR="\${SFANALYSIS_OUT_DIR:-\${SCRIPT_DIR}/out_httpd}"
mkdir -p "\$OUT_DIR"

# 很多固件（尤其 ASUS）会把“当前工作目录”当作 web 根目录，并用相对路径去打开页面/静态资源。
# 若在 / 启动，会出现：访问 / 能返回（通常是内置 CGI），但 /QIS_wizard.htm、/images/*、/*.css 全部 404。
# 优先把 cwd 切到 webroot（可通过 SFEMU_WEBROOT 手工覆盖）。
WEBROOT="\${SFEMU_WEBROOT:-}"
if [ -z "\$WEBROOT" ]; then
  if [ -d "\${SCRIPT_DIR}/www" ]; then
    WEBROOT="\${SCRIPT_DIR}/www"
  elif [ -d "\${SCRIPT_DIR}/var/www" ]; then
    WEBROOT="\${SCRIPT_DIR}/var/www"
  elif [ -d "\${SCRIPT_DIR}/home/httpd" ]; then
    WEBROOT="\${SCRIPT_DIR}/home/httpd"
  else
    WEBROOT="\${SCRIPT_DIR}"
  fi
fi
cd "\$WEBROOT" 2>/dev/null || cd "\${SCRIPT_DIR}"

exec "\${SCRIPT_DIR}/qemu-arm" -L "\${SCRIPT_DIR}" -rules "\${SCRIPT_DIR}/rules_examples/" -rules-ctx-keep 256 -rules-idle-ms 1000 \\
  -shadowstack log=off,summary=on,unwind_limit=100,max_stack=100 \\
  -sfanalysis "\$OUT_DIR" "${httpd_in_guest}"
EOF
  chmod +x "${rootfs}/start.sh"

  # ---- Docker 仿真 + curl 验证 ----
  if [[ "${FORCE_DOCKER}" != "0" ]]; then
    echo "[+] Docker emulate + curl..."
    docker run --rm --privileged \
      -e TERM \
      -v "${rootfs}:/rootfs:rw" \
      -v "${SFEMU_ROOT}:${SFEMU_ROOT}:rw" \
      -w /rootfs \
      "${IMAGE_TAG}" \
      /bin/bash -lc "
      set -euo pipefail

      mkdir -p /rootfs/sfemu_lab
      date -Is > /rootfs/sfemu_lab/docker.started_at

      # 启动：在容器内挂载必要文件系统，然后 chroot(rootfs) 运行 /start.sh（后台）。
      # 注意：不要依赖 mount_and_chroot.sh 的 CHROOT_CMD（脚本内未做安全引用，含引号会被拆词导致 chroot 立即退出）。
      ROOT=/rootfs
      is_mounted() { grep -qs \" \$1 \" /proc/mounts; }

      mkdir -p \"\${ROOT}/proc\" \"\${ROOT}/sys\" \"\${ROOT}/dev\" \"\${ROOT}/dev/pts\" \"\${ROOT}/tmp\" || true

      if ! is_mounted \"\${ROOT}/proc\"; then mount -t proc proc \"\${ROOT}/proc\"; fi
      if ! is_mounted \"\${ROOT}/sys\"; then mount -t sysfs sysfs \"\${ROOT}/sys\"; fi
      if ! is_mounted \"\${ROOT}/dev\"; then mount --bind /dev \"\${ROOT}/dev\"; fi
      if ! is_mounted \"\${ROOT}/dev/pts\"; then mount --bind /dev/pts \"\${ROOT}/dev/pts\"; fi

      # /tmp: 挂 tmpfs 前先 seed，避免 /etc -> /tmp/etc 这类固件布局把证书/配置“遮没了”
      seed_tmp_dir=\"\$(mktemp -d -t sfemu-rootfs-tmp-seed.XXXXXX)\"
      if [[ -d \"\${ROOT}/tmp\" ]]; then
        cp -a \"\${ROOT}/tmp/.\" \"\${seed_tmp_dir}/\" 2>/dev/null || true
      fi
      if ! is_mounted \"\${ROOT}/tmp\"; then
        mount -t tmpfs tmpfs \"\${ROOT}/tmp\"
      fi
      cp -a \"\${seed_tmp_dir}/.\" \"\${ROOT}/tmp/\" 2>/dev/null || true
      rm -rf -- \"\${seed_tmp_dir}\" 2>/dev/null || true

      # DNS/证书：让 chroot 内（qemu-user 触发的）python3/openssl 等工具能正常解析与走 HTTPS
      mkdir -p \"\${ROOT}/tmp/etc/ssl/certs\" 2>/dev/null || true
      cp -f /etc/resolv.conf \"\${ROOT}/tmp/etc/resolv.conf\" 2>/dev/null || true
      cp -f /etc/hosts \"\${ROOT}/tmp/etc/hosts\" 2>/dev/null || true
      cp -f /etc/nsswitch.conf \"\${ROOT}/tmp/etc/nsswitch.conf\" 2>/dev/null || true
      cp -f /etc/ssl/certs/ca-certificates.crt \"\${ROOT}/tmp/etc/ssl/certs/ca-certificates.crt\" 2>/dev/null || true

      # 后台启动 qemu-user(httpd)
      chroot \"\${ROOT}\" /start.sh > /rootfs/sfemu_lab/chroot_start.stdout.log 2> /rootfs/sfemu_lab/chroot_start.stderr.log &
      qpid=\$!
      echo \"\$qpid\" > /rootfs/sfemu_lab/chroot.pid

      # 等待服务启动：优先扫描 qemu-arm 监听端口；否则回退常见端口 80/443/8080
      detect_ports() {
        ss -lntpH 2>/dev/null | awk '/qemu-arm/ {print \$4}' | sed 's/.*://g' | tr -d '[]' | sort -n | uniq
      }

      try_curl() {
        local url=\"\$1\"
        local out_prefix=\"\$2\"
        if curl -m 2 -sS -D \"/rootfs/sfemu_lab/\${out_prefix}.hdr\" -o \"/rootfs/sfemu_lab/\${out_prefix}.body\" \"\$url\"; then
          echo \"\$url\" > /rootfs/sfemu_lab/success.url
          return 0
        fi
        return 1
      }

      try_curl_k() {
        local url=\"\$1\"
        local out_prefix=\"\$2\"
        if curl -k -m 3 -sS -D \"/rootfs/sfemu_lab/\${out_prefix}.hdr\" -o \"/rootfs/sfemu_lab/\${out_prefix}.body\" \"\$url\"; then
          echo \"\$url\" > /rootfs/sfemu_lab/success.url
          return 0
        fi
        return 1
      }

      ok=0
      for i in \$(seq 1 90); do
        ports=\"\$(detect_ports | tr '\\n' ' ')\"
        if [[ -z \"\$ports\" ]]; then
          ports=\"80 443 8080\"
        fi

        for p in \$ports; do
          # HTTP 优先
          if try_curl \"http://127.0.0.1:\${p}/\" \"curl_http_\${p}\"; then ok=1; break; fi
          # HTTPS 兜底
          if try_curl_k \"https://127.0.0.1:\${p}/\" \"curl_https_\${p}\"; then ok=1; break; fi
        done

        if [[ \"\$ok\" == \"1\" ]]; then
          break
        fi
        sleep 1
      done

      if [[ \"\$ok\" == \"1\" ]]; then
        echo \"success\" > /rootfs/sfemu_lab/result.status
      else
        echo \"fail\" > /rootfs/sfemu_lab/result.status
      fi
      ss -lntp > /rootfs/sfemu_lab/ss.lntp.txt 2>/dev/null || true

      # 收尾：尽力杀掉 qemu-arm（避免残留）；容器退出会自动回收 mount namespace
      kill \"\$qpid\" 2>/dev/null || true
      sleep 1 || true
      pkill -9 -f qemu-arm 2>/dev/null || true
      wait \"\$qpid\" 2>/dev/null || true

      date -Is > /rootfs/sfemu_lab/docker.finished_at
      exit 0
    " >"${lab_dir}/docker.stdout.log" 2>"${lab_dir}/docker.stderr.log" || true
  else
    echo "[=] Docker: 跳过（FORCE_DOCKER=0）"
  fi

  echo "[*] done: ${fw_name}"
}

while IFS= read -r line; do
  line="${line%%#*}"
  line="$(echo "${line}" | xargs || true)"
  [[ -z "${line}" ]] && continue

  httpd_abs="$(echo "${line}" | awk '{print $1}')"
  rootfs="$(echo "${line}" | awk '{print $2}')"

  if [[ ! -f "${httpd_abs}" ]]; then
    echo "[!] skip: httpd 不存在：${httpd_abs}" >&2
    continue
  fi
  if [[ ! -d "${rootfs}" ]]; then
    echo "[!] skip: rootfs 不存在：${rootfs}" >&2
    continue
  fi

  run_one "${httpd_abs}" "${rootfs}"
done < "${BATCH_FILE}"

echo "[+] batch 完成：${BATCH_FILE}"
