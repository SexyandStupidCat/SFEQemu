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

# AI/MCP（可选）：默认保持关闭，避免批量实验意外消耗 token 或误改文件系统。
# 如需启用（并允许 AI 做 filesystem 干预），示例：
#   AI_MCP_ENABLE=1 AI_MCP_TOOLS_ENABLE=1 AI_MCP_ACTIONS_ENABLE=1 \
#     ./lab/run_batch_001.sh lab/batch_001_asus_arm_httpd.txt
AI_ENABLE="${AI_ENABLE:-0}"
AI_MCP_ENABLE="${AI_MCP_ENABLE:-0}"
AI_MCP_TOOLS_ENABLE="${AI_MCP_TOOLS_ENABLE:-0}"
AI_MCP_ACTIONS_ENABLE="${AI_MCP_ACTIONS_ENABLE:-0}"
AI_MCP_SHELL_ENABLE="${AI_MCP_SHELL_ENABLE:-0}"
AI_MCP_NET_ENABLE="${AI_MCP_NET_ENABLE:-0}"
DOCKER_WAIT_SECS="${DOCKER_WAIT_SECS:-90}"

# Docker 行为控制（默认保持“批量脚本跑完即退出”的语义）
#
# 背景：批量脚本的 Docker 步骤会在 curl 验证成功后立刻退出容器并清理 qemu-arm，
# 这对“批量统计成功率”很友好，但如果你想在宿主机浏览器里打开页面，
# 容器会很快结束（看起来像“访问一下就退出”）。
#
# 用法示例（单固件调试/浏览器访问）：
#   DOCKER_KEEPALIVE=1 DOCKER_DETACH=1 DOCKER_PUBLISH=1 HOST_HTTP_PORT=18080 \
#     ./lab/run_batch_001.sh lab/batch_single_rt_ac1300uhp.txt
DOCKER_KEEPALIVE="${DOCKER_KEEPALIVE:-0}"   # 1=验证后不退出（保持 qemu-arm 运行）
DOCKER_DETACH="${DOCKER_DETACH:-0}"         # 1=后台启动容器（docker run -d）
DOCKER_RM="${DOCKER_RM:-1}"                 # 1=容器退出后自动删除（等价 --rm）
DOCKER_PUBLISH="${DOCKER_PUBLISH:-0}"       # 1=发布端口到宿主机（-p）
HOST_HTTP_PORT="${HOST_HTTP_PORT:-18080}"   # DOCKER_PUBLISH=1 时映射到宿主机的 HTTP 端口
HOST_HTTPS_PORT="${HOST_HTTPS_PORT:-18443}" # DOCKER_PUBLISH=1 时映射到宿主机的 HTTPS 端口

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

  # env：优先继承仓库内的 config/env（包含 OPENAI_* 等本地配置），再追加批量实验开关（覆盖同名键）。
  # 说明：
  # - 直接覆盖写死 env 会丢失 OPENAI_API_KEY，导致 AI MCP 无法调用；
  # - 这里采用“copy + append override”的方式，确保可控且可追溯。
  if [[ -f "${RULES_SRC}/config/env" ]]; then
    cp -f "${RULES_SRC}/config/env" "${rootfs}/rules_examples/config/env"
  else
    : >"${rootfs}/rules_examples/config/env"
  fi
  cat >>"${rootfs}/rules_examples/config/env" <<EOF

# ----------------------------
# 自动注入：批量仿真覆盖配置（可按固件覆盖）
# ----------------------------
SFEMU_AI_ENABLE=${AI_ENABLE}
SFEMU_AI_MCP_ENABLE=${AI_MCP_ENABLE}
SFEMU_AI_MCP_TOOLS_ENABLE=${AI_MCP_TOOLS_ENABLE}
SFEMU_AI_MCP_ACTIONS_ENABLE=${AI_MCP_ACTIONS_ENABLE}
SFEMU_AI_MCP_SHELL_ENABLE=${AI_MCP_SHELL_ENABLE}
SFEMU_AI_MCP_NET_ENABLE=${AI_MCP_NET_ENABLE}
SFEMU_AI_MCP_IP_BIN=/sfemu_tools/ip
SFEMU_AI_MCP_ASSUME_CONTAINER=1
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

    local ts container_name
    ts="$(date +%Y%m%d_%H%M%S)"
    container_name="sfemu-${fw_name}-${ts}"
    # Docker name 仅允许 [a-zA-Z0-9][a-zA-Z0-9_.-]，这里保守替换非法字符
    container_name="$(echo "${container_name}" | tr -c 'a-zA-Z0-9_.-' '_')"

    docker_args=(docker run)
    if [[ "${DOCKER_RM}" != "0" ]]; then
      docker_args+=(--rm)
    fi
    docker_args+=(--privileged -e TERM)
    if [[ "${DOCKER_PUBLISH}" != "0" ]]; then
      docker_args+=(-p "${HOST_HTTP_PORT}:80" -p "${HOST_HTTPS_PORT}:443")
    fi
    if [[ "${DOCKER_KEEPALIVE}" != "0" || "${DOCKER_DETACH}" != "0" ]]; then
      docker_args+=(--name "${container_name}")
    fi
    if [[ "${DOCKER_DETACH}" != "0" ]]; then
      docker_args+=(-d)
    fi
    docker_args+=(
      -v "${rootfs}:/rootfs:rw"
      -v "${SFEMU_ROOT}:${SFEMU_ROOT}:rw"
      -w /rootfs
      "${IMAGE_TAG}"
      /bin/bash -lc
    )

    "${docker_args[@]}" "
      set -euo pipefail
      KEEPALIVE=\"${DOCKER_KEEPALIVE}\"
      PUBLISH=\"${DOCKER_PUBLISH}\"
      HOST_HTTP_PORT=\"${HOST_HTTP_PORT}\"
      HOST_HTTPS_PORT=\"${HOST_HTTPS_PORT}\"
      CONTAINER_NAME=\"${container_name}\"
      WAIT_SECS=\"${DOCKER_WAIT_SECS}\"

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

      # ---- AI MCP 依赖（x86_64 python3 + 动态库）----
      # 背景：qemu-arm 在 chroot(rootfs) 内运行时，固件一般不自带 python3；
      # 但 AI MCP 插件（ai_mcp_openai.py）需要 python3（x86_64）访问 OpenAI 兼容 API。
      # 方案：把容器内的 x86_64 python3 及其运行时目录“只读 bind mount”进 rootfs 的非冲突路径：
      # - /usr/bin/python3（文件级 bind mount）
      # - /lib64 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu（目录 bind mount）
      # - /usr/lib/pythonX.Y /usr/lib/python3（标准库）
      need_ai=0
      if grep -qs '^SFEMU_AI_MCP_ENABLE=1' \"\${ROOT}/rules_examples/config/env\"; then need_ai=1; fi
      if grep -qs '^SFEMU_AI_ENABLE=1' \"\${ROOT}/rules_examples/config/env\"; then need_ai=1; fi
      if [[ \"\${need_ai}\" == \"1\" ]]; then
        mkdir -p \"\${ROOT}/usr/bin\" \"\${ROOT}/usr/lib\" \"\${ROOT}/lib\" \"\${ROOT}/lib64\" 2>/dev/null || true
        # python3 binary
        if [[ -x /usr/bin/python3 ]]; then
          if [[ ! -e \"\${ROOT}/usr/bin/python3\" ]]; then
            : >\"\${ROOT}/usr/bin/python3\" 2>/dev/null || true
            chmod +x \"\${ROOT}/usr/bin/python3\" 2>/dev/null || true
          fi
          mount --bind /usr/bin/python3 \"\${ROOT}/usr/bin/python3\" 2>/dev/null || true
        fi
        # dynamic loader + glibc
        if [[ -d /lib64 ]]; then
          mkdir -p \"\${ROOT}/lib64\" 2>/dev/null || true
          mount --bind /lib64 \"\${ROOT}/lib64\" 2>/dev/null || true
        fi
        if [[ -d /lib/x86_64-linux-gnu ]]; then
          mkdir -p \"\${ROOT}/lib/x86_64-linux-gnu\" 2>/dev/null || true
          mount --bind /lib/x86_64-linux-gnu \"\${ROOT}/lib/x86_64-linux-gnu\" 2>/dev/null || true
        fi
        if [[ -d /usr/lib/x86_64-linux-gnu ]]; then
          mkdir -p \"\${ROOT}/usr/lib/x86_64-linux-gnu\" 2>/dev/null || true
          mount --bind /usr/lib/x86_64-linux-gnu \"\${ROOT}/usr/lib/x86_64-linux-gnu\" 2>/dev/null || true
        fi
        # python stdlib（ubuntu:24.04 默认 python3.12；若未来版本变更，可按需扩展）
        if [[ -d /usr/lib/python3.12 ]]; then
          mkdir -p \"\${ROOT}/usr/lib/python3.12\" 2>/dev/null || true
          mount --bind /usr/lib/python3.12 \"\${ROOT}/usr/lib/python3.12\" 2>/dev/null || true
        fi
        if [[ -d /usr/lib/python3 ]]; then
          mkdir -p \"\${ROOT}/usr/lib/python3\" 2>/dev/null || true
          mount --bind /usr/lib/python3 \"\${ROOT}/usr/lib/python3\" 2>/dev/null || true
        fi

        # iproute2（供 AI MCP net_* 工具使用）：避免依赖固件自带 ip/ifconfig
        mkdir -p \"\${ROOT}/sfemu_tools\" 2>/dev/null || true
        if [[ -x /usr/sbin/ip ]]; then
          if [[ ! -e \"\${ROOT}/sfemu_tools/ip\" ]]; then
            : >\"\${ROOT}/sfemu_tools/ip\" 2>/dev/null || true
            chmod +x \"\${ROOT}/sfemu_tools/ip\" 2>/dev/null || true
          fi
          mount --bind /usr/sbin/ip \"\${ROOT}/sfemu_tools/ip\" 2>/dev/null || true
        fi
      fi

      # 后台启动 qemu-user(httpd)
      qpid=\"\"
      cleanup() {
        set +e
        # 收尾：尽力杀掉 qemu-arm（避免残留）；容器退出会自动回收 mount namespace
        if [[ -n \"\${qpid}\" ]]; then
          kill \"\${qpid}\" 2>/dev/null || true
          sleep 1 || true
          wait \"\${qpid}\" 2>/dev/null || true
        fi
        pkill -9 -f qemu-arm 2>/dev/null || true
        date -Is > /rootfs/sfemu_lab/docker.finished_at
      }
      trap cleanup EXIT

      chroot \"\${ROOT}\" /start.sh > /rootfs/sfemu_lab/chroot_start.stdout.log 2> /rootfs/sfemu_lab/chroot_start.stderr.log &
      qpid=\$!
      echo \"\$qpid\" > /rootfs/sfemu_lab/chroot.pid

      # 等待服务启动：优先扫描 qemu-arm 监听端口；否则回退常见端口 80/443/8080
      detect_listeners() {
        # 输出：addr port（空格分隔）。过滤掉 0.0.0.0/:: 时，后续会回退到 127.0.0.1。
        ss -lntpH 2>/dev/null | awk '{print \$4}' | sed 's/\\[//g; s/\\]//g' | awk -F: 'NF>=2 {port=\$NF; \$NF=\"\"; addr=\$0; sub(/:$/, \"\", addr); print addr\" \"port}' | sort -u
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
      for i in \$(seq 1 \"\${WAIT_SECS}\"); do
        # 目标 host 列表：尽量覆盖“绑定到 lan_ipaddr/容器 IP/0.0.0.0”的固件
        eth0_ip=\"\$(ip -4 -o addr show dev eth0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | head -n1 || true)\"
        hosts=\"127.0.0.1 localhost\"
        if [[ -n \"\${eth0_ip}\" ]]; then
          hosts=\"\${hosts} \${eth0_ip}\"
        fi
        hosts=\"\${hosts} 192.168.1.1 192.168.0.1 192.168.50.1 10.0.0.1\"

        listeners=\"\$(detect_listeners | head -n 50 || true)\"

        # 端口优先级：先从监听列表提取；否则回退常见端口
        ports=\"\$(echo \"\${listeners}\" | awk '{print \$2}' | tr '\\n' ' ' | sort -n | uniq)\"
        if [[ -z \"\$ports\" ]]; then
          ports=\"80 443 8080\"
        fi

        for p in \$ports; do
          for h in \$hosts; do
            if try_curl \"http://\${h}:\${p}/\" \"curl_http_\${h}_\${p}\"; then ok=1; break; fi
            if try_curl_k \"https://\${h}:\${p}/\" \"curl_https_\${h}_\${p}\"; then ok=1; break; fi
          done
          if [[ \"\$ok\" == \"1\" ]]; then
            break
          fi
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

      if [[ \"\${KEEPALIVE}\" == \"1\" ]]; then
        date -Is > /rootfs/sfemu_lab/docker.ready_at
        echo \"[docker] KEEPALIVE=1：保持容器运行（不自动退出/不杀 qemu-arm）\"
        if [[ \"\${PUBLISH}\" == \"1\" ]]; then
          echo \"[docker] 宿主机可访问：\"
          echo \"  http://127.0.0.1:\${HOST_HTTP_PORT}/QIS_wizard.htm?flag=welcome\"
          echo \"  https://127.0.0.1:\${HOST_HTTPS_PORT}/  (若固件启了 HTTPS)\"
	        else
	          echo \"[docker] 未发布端口（DOCKER_PUBLISH=0）。若宿主机能直连容器网段，可用容器 IP 访问。\"
	          ip -4 -o addr show dev eth0 2>/dev/null || true
	        fi
        echo \"[docker] 容器名：\${CONTAINER_NAME}\"
        echo \"[docker] 停止：docker stop \${CONTAINER_NAME}\"
        # 阻塞保持运行（可改为 tail -f 观察日志）
        while true; do sleep 3600; done
      fi

      exit 0
    " >"${lab_dir}/docker.stdout.log" 2>"${lab_dir}/docker.stderr.log" || true

    # detach 模式下，docker stdout 是 container id，落到 docker.stdout.log；额外写一份便于脚本/人读取
    if [[ "${DOCKER_DETACH}" != "0" ]]; then
      local cid
      cid="$(head -n 1 "${lab_dir}/docker.stdout.log" 2>/dev/null | tr -d $'\r\n' || true)"
      if [[ -n "${cid}" ]]; then
        echo "${cid}" > "${lab_dir}/docker.container_id"
        echo "${container_name}" > "${lab_dir}/docker.container_name"
        echo "[+] Docker 已后台启动：name=${container_name} id=${cid}"
        if [[ "${DOCKER_PUBLISH}" != "0" ]]; then
          echo "[+] 浏览器访问：http://127.0.0.1:${HOST_HTTP_PORT}/QIS_wizard.htm?flag=welcome"
        fi
      else
        echo "[!] Docker 后台启动失败：未拿到 container id（见 ${lab_dir}/docker.stderr.log）" >&2
      fi
    fi
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
