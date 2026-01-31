#!/usr/bin/env bash
set -euo pipefail

# 批量实验脚本（批次 001）
#
# 功能：
# 1) SDGen：生成依赖图/启动序列（sdg.json）
# 2) SFAnalysis：生成静态分析结果（out_httpd/，含伪C）
# 3) 注入：qemu-user（按架构选择）、mount_and_chroot.sh、rules_examples、start.sh、env
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
QEMU_MIPS_SRC="${WORKSPACE_ROOT}/rootfs/qemu-mips"
QEMU_MIPSEL_SRC="${WORKSPACE_ROOT}/rootfs/qemu-mipsel"
MOUNT_SRC="${WORKSPACE_ROOT}/rootfs/mount_and_chroot.sh"
RULES_SRC="${SFEQEMU_ROOT}/rules_examples"
FORCE_SDGEN="${FORCE_SDGEN:-0}"
FORCE_SFANALYSIS="${FORCE_SFANALYSIS:-0}"
FORCE_DOCKER="${FORCE_DOCKER:-1}"
EMU_ONLY="${EMU_ONLY:-0}" # 1=仅做动态仿真（跳过 SDGen/SFAnalysis，加速批量实验）
SKIP_SDGEN="${SKIP_SDGEN:-${EMU_ONLY}}"
SKIP_SFANALYSIS="${SKIP_SFANALYSIS:-${EMU_ONLY}}"

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
if [[ ! -x "${QEMU_MIPS_SRC}" ]]; then
  echo "[!] qemu-mips 不存在/不可执行：${QEMU_MIPS_SRC}" >&2
  exit 1
fi
if [[ ! -x "${QEMU_MIPSEL_SRC}" ]]; then
  echo "[!] qemu-mipsel 不存在/不可执行：${QEMU_MIPSEL_SRC}" >&2
  echo "    解决：在仓库内构建 qemu-mipsel 并安装到 workspace/rootfs（或直接放置该文件）。" >&2
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

  # ---- 根据服务程序架构选择 qemu-user ----
  local file_out arch qemu_src qemu_name
  file_out="$(file -b "${httpd_abs}" 2>/dev/null || true)"
  if [[ "${file_out}" == *"ARM"* ]]; then
    arch="arm"
    qemu_src="${QEMU_ARM_SRC}"
    qemu_name="qemu-arm"
  elif [[ "${file_out}" == *"MIPS"* && "${file_out}" == *"LSB"* ]]; then
    arch="mipsel"
    qemu_src="${QEMU_MIPSEL_SRC}"
    qemu_name="qemu-mipsel"
  elif [[ "${file_out}" == *"MIPS"* && "${file_out}" == *"MSB"* ]]; then
    arch="mips"
    qemu_src="${QEMU_MIPS_SRC}"
    qemu_name="qemu-mips"
  else
    arch="unknown"
    qemu_src=""
    qemu_name=""
  fi
  echo "${file_out}" >"${lab_dir}/service.file.txt" 2>/dev/null || true
  echo "${arch}" >"${lab_dir}/service.arch" 2>/dev/null || true
  echo "${qemu_name}" >"${lab_dir}/qemu.bin" 2>/dev/null || true

  echo "========== ${fw_name} =========="
  echo "[*] httpd: ${httpd_abs}"
  echo "[*] rootfs: ${rootfs}"
  echo "[*] arch: ${arch} (qemu=${qemu_name})"

  if [[ -z "${qemu_src}" || -z "${qemu_name}" ]]; then
    echo "[!] skip: 不支持的服务程序架构：${file_out}" >&2
    echo "fail" >"${lab_dir}/result.status" 2>/dev/null || true
    echo "unsupported_arch" >"${lab_dir}/fail.reason" 2>/dev/null || true
    return 0
  fi

  # ---- 注入：qemu-user / mount 脚本 / rules_examples ----
  install -m 0755 "${qemu_src}" "${rootfs}/${qemu_name}"
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
SFEMU_NO_PROMPT=1
SFEMU_AI_AUTO_CONTINUE=1
SFEMU_AI_APPLY_RULES=1
SFEMU_AI_APPLY_OBSERVE=0
SFEMU_AI_OVERWRITE_RULES=0
SFEMU_AI_VERIFY_SYSCALLS=2048
SFEMU_AI_DISABLE_AFTER_STABLE=1
# 仅启用人工 override（每固件特有规则），避免历史遗留的 AI override 干扰通用基线规则
SFEMU_RULES_OVERRIDE_DIR=syscall_override_user
SFEMU_LOG_RULE_LOAD=0
auto_ai=${AI_ENABLE}
EOF

  # ---- SDGen：依赖图/启动序列 ----
  if [[ "${SKIP_SDGEN}" == "1" ]]; then
    echo "[=] SDGen: SKIP_SDGEN=1 跳过"
  else
    if [[ "${FORCE_SDGEN}" == "1" || ! -s "${lab_dir}/sdg.json" ]]; then
      echo "[+] SDGen..."
      (
        cd "${SDGEN_ROOT}"
        python3 find_need.py "${httpd_abs}" "${rootfs}" "${lab_dir}/sdg.json" 10 --min-confidence=0.8
      ) >"${lab_dir}/sdgen.stdout.log" 2>"${lab_dir}/sdgen.stderr.log" || true
    else
      echo "[=] SDGen: 已存在 ${lab_dir}/sdg.json，跳过（FORCE_SDGEN=1 可强制）"
    fi
  fi

  # ---- SFAnalysis：静态分析（伪C）----
  if [[ "${SKIP_SFANALYSIS}" == "1" ]]; then
    echo "[=] SFAnalysis: SKIP_SFANALYSIS=1 跳过"
  else
    if [[ "${FORCE_SFANALYSIS}" == "1" || -z "$(find "${rootfs}/out_httpd" -maxdepth 1 -name '*.json' -print -quit 2>/dev/null)" ]]; then
      echo "[+] SFAnalysis..."
      (
        cd "${SFANALYSIS_ROOT}"
        python3 pyghidra_fw_analyze.py --binary "${httpd_abs}" --fs-root "${rootfs}" --out-dir "${rootfs}/out_httpd" --emit-pseudocode
      ) >"${lab_dir}/sfanalysis.stdout.log" 2>"${lab_dir}/sfanalysis.stderr.log" || true
    else
      echo "[=] SFAnalysis: 已存在 ${rootfs}/out_httpd/*.json，跳过（FORCE_SFANALYSIS=1 可强制）"
    fi
  fi

  # ---- start.sh：固件内启动 Web 服务（qemu-user + rules + sfanalysis）----
  local httpd_in_guest="${httpd_abs#${rootfs}}"
  if [[ "${httpd_in_guest}" == "${httpd_abs}" ]]; then
    # 兜底：如果无法直接剥离 rootfs 前缀，则回退用常见路径
    httpd_in_guest="/usr/sbin/httpd"
  fi

  if [[ "${SKIP_SFANALYSIS}" == "1" ]]; then
    cat >"${rootfs}/start.sh" <<EOF
#!/bin/sh
set -e

# 很多固件（尤其 ASUS）会把“当前工作目录”当作 web 根目录，并用相对路径去打开页面/静态资源。
# 若在 / 启动，会出现：访问 / 能返回（通常是内置 CGI），但 /QIS_wizard.htm、/images/*、/*.css 全部 404。
# 优先把 cwd 切到 webroot（可通过 SFEMU_WEBROOT 手工覆盖）。
WEBROOT="\${SFEMU_WEBROOT:-}"
if [ -z "\$WEBROOT" ]; then
  if [ -d "/www" ]; then
    WEBROOT="/www"
  elif [ -d "/var/www" ]; then
    WEBROOT="/var/www"
  elif [ -d "/home/httpd" ]; then
    WEBROOT="/home/httpd"
  else
    WEBROOT="/"
  fi
fi
cd "\$WEBROOT" 2>/dev/null || cd "/"

exec "/${qemu_name}" -L "/" -rules "/rules_examples/" -rules-ctx-keep 256 -rules-idle-ms 1000 \\
  -shadowstack log=off,summary=on,unwind_limit=100,max_stack=100 \\
  "${httpd_in_guest}"
EOF
  else
    cat >"${rootfs}/start.sh" <<EOF
#!/bin/sh
set -e

OUT_DIR="\${SFANALYSIS_OUT_DIR:-/out_httpd}"
mkdir -p "\$OUT_DIR" 2>/dev/null || true

# 很多固件（尤其 ASUS）会把“当前工作目录”当作 web 根目录，并用相对路径去打开页面/静态资源。
# 若在 / 启动，会出现：访问 / 能返回（通常是内置 CGI），但 /QIS_wizard.htm、/images/*、/*.css 全部 404。
# 优先把 cwd 切到 webroot（可通过 SFEMU_WEBROOT 手工覆盖）。
WEBROOT="\${SFEMU_WEBROOT:-}"
if [ -z "\$WEBROOT" ]; then
  if [ -d "/www" ]; then
    WEBROOT="/www"
  elif [ -d "/var/www" ]; then
    WEBROOT="/var/www"
  elif [ -d "/home/httpd" ]; then
    WEBROOT="/home/httpd"
  else
    WEBROOT="/"
  fi
fi
cd "\$WEBROOT" 2>/dev/null || cd "/"

exec "/${qemu_name}" -L "/" -rules "/rules_examples/" -rules-ctx-keep 256 -rules-idle-ms 1000 \\
  -shadowstack log=off,summary=on,unwind_limit=100,max_stack=100 \\
  -sfanalysis "\$OUT_DIR" "${httpd_in_guest}"
EOF
  fi
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
      # 清理上一次运行的遗留产物，避免“旧成功/旧 curl 结果”干扰本次统计
      rm -f /rootfs/sfemu_lab/result.status /rootfs/sfemu_lab/success.url /rootfs/sfemu_lab/ss.lntp.txt 2>/dev/null || true
      rm -f /rootfs/sfemu_lab/curl_http_* /rootfs/sfemu_lab/curl_https_* 2>/dev/null || true

      # 启动：在容器内挂载必要文件系统，然后 chroot(rootfs) 运行 /start.sh（后台）。
      # 注意：不要依赖 mount_and_chroot.sh 的 CHROOT_CMD（脚本内未做安全引用，含引号会被拆词导致 chroot 立即退出）。
      ROOT=/rootfs
      is_mounted() { grep -qs \" \$1 \" /proc/mounts; }

      # 某些固件 rootfs 会把 /dev(/proc,/sys) 做成 symlink（甚至 /dev -> /dev/null），直接 mount 会失败。
      # 这里统一把 mountpoint 解析到“真实目录”，保证可挂载。
      resolve_root_mount() {
        local p=\"\$1\"         # 形如 /dev /proc /sys
        local mp=\"\${ROOT}\${p}\"
        if [[ -L \"\${mp}\" ]]; then
          local link=\"\$(readlink \"\${mp}\" 2>/dev/null || true)\"
          # /dev -> /dev/null：直接替换为目录（否则 bind mount 无法进行）
          if [[ \"\${link}\" == \"/dev/null\" ]]; then
            rm -f \"\${mp}\" 2>/dev/null || true
            mkdir -p \"\${mp}\" 2>/dev/null || true
            echo \"\${mp}\"
            return 0
          fi
          if [[ -n \"\${link}\" ]]; then
            if [[ \"\${link}\" == /* ]]; then
              mp=\"\${ROOT}\${link}\"
            else
              mp=\"\${ROOT}/\${link}\"
            fi
          fi
        fi
        if [[ -e \"\${mp}\" && ! -d \"\${mp}\" ]]; then
          rm -f \"\${mp}\" 2>/dev/null || true
        fi
        mkdir -p \"\${mp}\" 2>/dev/null || true
        echo \"\${mp}\"
        return 0
      }

      proc_mp=\"\$(resolve_root_mount /proc)\"
      sys_mp=\"\$(resolve_root_mount /sys)\"
      dev_mp=\"\$(resolve_root_mount /dev)\"
      pts_mp=\"\${dev_mp}/pts\"
      mkdir -p \"\${pts_mp}\" 2>/dev/null || true

      if ! is_mounted \"\${proc_mp}\"; then mount -t proc proc \"\${proc_mp}\"; fi
      if ! is_mounted \"\${sys_mp}\"; then mount -t sysfs sysfs \"\${sys_mp}\"; fi
      if ! is_mounted \"\${dev_mp}\"; then mount --bind /dev \"\${dev_mp}\"; fi
      if ! is_mounted \"\${pts_mp}\"; then mount --bind /dev/pts \"\${pts_mp}\"; fi

      # /tmp：兼容固件把 /tmp 做成坏 symlink 的情况（指向不存在/文件/循环）。
      tmp_mount=\"\${ROOT}/tmp\"
      if [[ -L \"\${ROOT}/tmp\" ]]; then
        link=\"\$(readlink \"\${ROOT}/tmp\" 2>/dev/null || true)\"
        if [[ -n \"\${link}\" ]]; then
          if [[ \"\${link}\" == /* ]]; then
            tmp_mount=\"\${ROOT}\${link}\"
          else
            tmp_mount=\"\${ROOT}/\${link}\"
          fi
        fi
      fi
      mkdir -p \"\${tmp_mount}\" 2>/dev/null || true
      if [[ ! -d \"\${tmp_mount}\" ]]; then
        rm -f \"\${ROOT}/tmp\" 2>/dev/null || true
        mkdir -p \"\${ROOT}/tmp\" 2>/dev/null || true
        tmp_mount=\"\${ROOT}/tmp\"
      fi

      # /tmp: 挂 tmpfs 前先 seed，避免 /etc -> /tmp/etc 这类固件布局把证书/配置“遮没了”
      seed_tmp_dir=\"\$(mktemp -d -t sfemu-rootfs-tmp-seed.XXXXXX)\"
      if [[ -d \"\${tmp_mount}\" ]]; then
        cp -a \"\${tmp_mount}/.\" \"\${seed_tmp_dir}/\" 2>/dev/null || true
      fi
      if ! is_mounted \"\${tmp_mount}\"; then
        mount -t tmpfs tmpfs \"\${tmp_mount}\"
      fi
      cp -a \"\${seed_tmp_dir}/.\" \"\${tmp_mount}/\" 2>/dev/null || true
      rm -rf -- \"\${seed_tmp_dir}\" 2>/dev/null || true

      # /etc：部分固件为了只读化/节省空间，会把 /etc 指向 /dev/null（或做成非目录），导致程序打开 /etc/* 直接 -ENOTDIR。
      # 这里统一确保“chroot 内的 /etc 可用”：
      # - 若 /etc -> /dev/null：改为 /etc -> /tmp/etc（复用我们在 tmpfs 里注入的 DNS/证书等文件）
      # - 若 /etc 是普通文件：备份后改为目录
      if [[ -L \"\${ROOT}/etc\" ]]; then
        elink=\"\$(readlink \"\${ROOT}/etc\" 2>/dev/null || true)\"
        if [[ \"\${elink}\" == \"/dev/null\" ]]; then
          rm -f \"\${ROOT}/etc\" 2>/dev/null || true
          mkdir -p \"\${ROOT}/tmp/etc\" 2>/dev/null || true
          ln -s \"/tmp/etc\" \"\${ROOT}/etc\" 2>/dev/null || true
        elif [[ -n \"\${elink}\" ]]; then
          # 其它 symlink：尽量保证目标目录存在
          if [[ \"\${elink}\" == /* ]]; then
            mkdir -p \"\${ROOT}\${elink}\" 2>/dev/null || true
          else
            mkdir -p \"\${ROOT}/\${elink}\" 2>/dev/null || true
          fi
        fi
      elif [[ -e \"\${ROOT}/etc\" && ! -d \"\${ROOT}/etc\" ]]; then
        mv -f \"\${ROOT}/etc\" \"\${ROOT}/etc.bak\" 2>/dev/null || true
        mkdir -p \"\${ROOT}/etc\" 2>/dev/null || true
      else
        mkdir -p \"\${ROOT}/etc\" 2>/dev/null || true
      fi

      # /var：数据集里存在把 /var 指向 /dev/null 的固件（节省空间/只读化），会导致
      # - /var/run/*.pid 创建失败（Not a directory）
      # - /var/lock/*、/var/log/* 等路径不可写
      #
      # 这里做最小可写修复：
      # 1) 若 /var -> /dev/null，直接替换为目录；
      # 2) 若 /var 是其它 symlink，确保其目标目录存在；
      # 3) 若 /var 是普通文件，备份后改为目录。
      if [[ -L \"\${ROOT}/var\" ]]; then
        vlink=\"\$(readlink \"\${ROOT}/var\" 2>/dev/null || true)\"
        if [[ \"\${vlink}\" == \"/dev/null\" ]]; then
          rm -f \"\${ROOT}/var\" 2>/dev/null || true
          mkdir -p \"\${ROOT}/var\" 2>/dev/null || true
        elif [[ -n \"\${vlink}\" ]]; then
          if [[ \"\${vlink}\" == /* ]]; then
            mkdir -p \"\${ROOT}\${vlink}\" 2>/dev/null || true
          else
            mkdir -p \"\${ROOT}/\${vlink}\" 2>/dev/null || true
          fi
        fi
      elif [[ -e \"\${ROOT}/var\" && ! -d \"\${ROOT}/var\" ]]; then
        mv -f \"\${ROOT}/var\" \"\${ROOT}/var.bak\" 2>/dev/null || true
        mkdir -p \"\${ROOT}/var\" 2>/dev/null || true
      else
        mkdir -p \"\${ROOT}/var\" 2>/dev/null || true
      fi
      mkdir -p \"\${ROOT}/var/run\" \"\${ROOT}/var/lock\" \"\${ROOT}/var/log\" 2>/dev/null || true

      # DNS/证书：让 chroot 内（qemu-user 触发的）python3/openssl 等工具能正常解析与走 HTTPS
      mkdir -p \"\${ROOT}/tmp/etc/ssl/certs\" 2>/dev/null || true
      cp -f /etc/resolv.conf \"\${ROOT}/tmp/etc/resolv.conf\" 2>/dev/null || true
      cp -f /etc/hosts \"\${ROOT}/tmp/etc/hosts\" 2>/dev/null || true
      cp -f /etc/nsswitch.conf \"\${ROOT}/tmp/etc/nsswitch.conf\" 2>/dev/null || true
      cp -f /etc/ssl/certs/ca-certificates.crt \"\${ROOT}/tmp/etc/ssl/certs/ca-certificates.crt\" 2>/dev/null || true

      # 一些固件会读取 /etc/TZ、/etc/passwd；若缺失则补最小文件（放在 /tmp/etc，若 /etc->/tmp/etc 则自动生效）
      if [[ ! -f \"\${ROOT}/tmp/etc/TZ\" ]]; then
        echo \"UTC\" > \"\${ROOT}/tmp/etc/TZ\" 2>/dev/null || true
      fi
      if [[ ! -f \"\${ROOT}/tmp/etc/passwd\" ]]; then
        printf '%s\\n' 'root:x:0:0:root:/root:/bin/sh' > \"\${ROOT}/tmp/etc/passwd\" 2>/dev/null || true
      fi

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
        pkill -9 -f '/qemu-' 2>/dev/null || true
        date -Is > /rootfs/sfemu_lab/docker.finished_at
      }
      trap cleanup EXIT

      # 后台启动 qemu-user(websvc)
      # 重要：不要依赖固件自带 /bin/sh 来执行 /start.sh。
      # - 很多数据集 rootfs 缺 /bin/sh，或 /bin/sh 损坏/不可执行，导致 chroot 直接报 ENOENT/EACCES；
      # - 也有不少 busybox shell 语法能力不足，会把我们注入脚本里的参数展开当成“未定义变量”。
      # 因此这里直接在容器侧拼好命令，并用 chroot 直接执行 /qemu-* + 目标服务。
      QEMU_BIN=\"/${qemu_name}\"
      GUEST_BIN=\"${httpd_in_guest}\"

      # 选择 webroot（用于固件相对路径打开静态资源时避免 404）
      pick_webroot_host() {
        local override=\"\"
        if [[ -f \"\${ROOT}/rules_examples/config/env\" ]]; then
          override=\"\$(grep -E '^SFEMU_WEBROOT=' \"\${ROOT}/rules_examples/config/env\" | tail -n 1 | cut -d= -f2- || true)\"
        fi
        if [[ -n \"\${override}\" ]]; then
          if [[ \"\${override}\" == /* && -d \"\${ROOT}\${override}\" ]]; then echo \"\${ROOT}\${override}\"; return 0; fi
          if [[ -d \"\${ROOT}/\${override}\" ]]; then echo \"\${ROOT}/\${override}\"; return 0; fi
        fi
        if [[ -d \"\${ROOT}/www\" ]]; then echo \"\${ROOT}/www\"; return 0; fi
        if [[ -d \"\${ROOT}/var/www\" ]]; then echo \"\${ROOT}/var/www\"; return 0; fi
        if [[ -d \"\${ROOT}/home/httpd\" ]]; then echo \"\${ROOT}/home/httpd\"; return 0; fi
        echo \"\${ROOT}\"; return 0
      }

      WEBROOT_HOST=\"\$(pick_webroot_host)\"
      cd \"\${WEBROOT_HOST}\" 2>/dev/null || cd \"\${ROOT}\"

      guest_args=()
      guest_base=\"\$(basename \"\${GUEST_BIN}\" 2>/dev/null || echo \"\")\"

      # lighttpd：自动补齐 -f <conf>
      if [[ \"\${guest_base}\" == \"lighttpd\" ]]; then
        conf=\"\"
        for p in /etc/lighttpd/lighttpd.conf /etc/lighttpd.conf /etc/lighttpd/lighttpd.conf; do
          if [[ -f \"\${ROOT}\${p}\" ]]; then conf=\"\${p}\"; break; fi
        done
        if [[ -n \"\${conf}\" ]]; then
          guest_args+=( -f \"\${conf}\" )
        fi

        # ZyXEL/OpenWrt 系 lighttpd 常见：lighttpd.conf include 了 conf.d/*.conf，
        # 但数据集里可能缺这些文件，lighttpd 会直接退出。
        # 这里按 include 列表补齐缺失文件：
        # - port.conf：写入最小端口配置
        # - 其他 conf：先用空文件占位（避免解析失败）
        if [[ -f \"\${ROOT}/etc/lighttpd/lighttpd.conf\" ]]; then
          mkdir -p \"\${ROOT}/etc/lighttpd/conf.d\" 2>/dev/null || true
          while IFS= read -r inc; do
            name=\"\$(echo \"\${inc}\" | sed -E 's/.*\"conf\\.d\\/([^\\\"]+)\".*/\\1/' || true)\"
            [[ -z \"\${name}\" ]] && continue
            target=\"\${ROOT}/etc/lighttpd/conf.d/\${name}\"
            if [[ ! -f \"\${target}\" ]]; then
              if [[ \"\${name}\" == \"port.conf\" ]]; then
                cat > \"\${target}\" <<'EOF_PORTCONF'
server.port = 80
EOF_PORTCONF
              else
                : > \"\${target}\"
              fi
            fi
          done < <(grep -E '^[[:space:]]*include[[:space:]]+\"conf\\.d/[^\\\"]+\"' \"\${ROOT}/etc/lighttpd/lighttpd.conf\" 2>/dev/null || true)
        fi
      fi

      # 一些 ipcamera 的 /web/httpd 变体必须带端口参数，否则直接打印 usage 并退出
      if [[ \"\${guest_base}\" == \"httpd\" && \"\${GUEST_BIN}\" == \"/web/httpd\" ]]; then
        guest_args+=( 80 )
      fi

      # uhttpd（OpenWrt）：若未通过 init 读取配置，可能不绑定任何端口，直接报 “No sockets bound”
      if [[ \"\${guest_base}\" == \"uhttpd\" ]]; then
        if [[ -d \"\${ROOT}/www\" ]]; then
          guest_args+=( -p 0.0.0.0:80 -h /www )
        else
          guest_args+=( -p 0.0.0.0:80 )
        fi
      fi

      qemu_args=( \"\${QEMU_BIN}\" -L / -rules /rules_examples/ -rules-ctx-keep 256 -rules-idle-ms 1000 \\
        -shadowstack log=off,summary=on,unwind_limit=100,max_stack=100 )

      USE_SFANALYSIS=\"0\"
      if [[ \"${SKIP_SFANALYSIS}\" != \"1\" ]]; then
        USE_SFANALYSIS=\"1\"
      fi
      if [[ \"\${USE_SFANALYSIS}\" == \"1\" ]]; then
        qemu_args+=( -sfanalysis /out_httpd )
      fi

      chroot \"\${ROOT}\" \"\${qemu_args[@]}\" \"\${GUEST_BIN}\" \"\${guest_args[@]}\" > /rootfs/sfemu_lab/chroot_start.stdout.log 2> /rootfs/sfemu_lab/chroot_start.stderr.log &
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
