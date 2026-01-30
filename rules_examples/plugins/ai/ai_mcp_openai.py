#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai_mcp_openai.py - 内置“类 MCP”能力：读取快照 -> 调用 OpenAI 兼容 API -> 生成 Lua 规则文件

用法：
  python3 ai_mcp_openai.py <snapshot.json> <rules_patch_dir> <env_path>

输出约定：
  - 修复型规则：<rules_patch_dir>/fix/syscall/<name>.lua
  - 观测型规则：<rules_patch_dir>/observe/syscall/<name>.lua

说明：
  - 本脚本作为 rules/plugins/ 下的插件式工具使用。
  - 本脚本只负责“生成规则文件”；是否应用/验证/导出 stable_rules 由 base/ai.lua 负责。
  - env 文件中读取：OPENAI_API_KEY / OPENAI_BASE_URL / OPENAI_MODEL

扩展能力（可选）：
  - 支持 OpenAI “tools/tool_calls” 接口：模型可调用一组受限的“干预工具”（文件读写、目录创建、软链等）
  - 即使网关不支持 tools，也可在最终 JSON 中输出 "actions"（脚本会按白名单执行并记录到 ai_actions.json）

安全边界（默认偏保守，可通过 env 调整）：
  - 仅当检测到“在固件 rootfs 环境”时才允许写入（避免误写宿主机）
  - 允许写入的路径必须位于 safe_root（通常为 / 或 <rootfs>）
  - shell 执行默认关闭（避免在不可信环境下执行任意命令）
"""

from __future__ import annotations

import base64
import glob
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Any, Tuple, Optional, List


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)

def str_bool(v: Optional[str], default: bool) -> bool:
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return default


def clamp_int(v: Optional[str], lo: int, hi: int, default: int) -> int:
    try:
        n = int(str(v).strip())
    except Exception:
        return default
    if n < lo:
        return lo
    if n > hi:
        return hi
    return n


def load_env(env_path: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                if line.startswith("export "):
                    line = line[len("export ") :].lstrip()
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip()
                if not k:
                    continue
                if len(v) >= 2 and ((v[0] == v[-1] == "'") or (v[0] == v[-1] == '"')):
                    v = v[1:-1]
                env[k] = v
    except FileNotFoundError:
        return env
    except Exception as ex:
        eprint(f"[ai_mcp_openai] 读取 env 失败: {ex}")
        return env
    return env


def normalize_chat_completions_url(base: str) -> str:
    base = (base or "").strip()
    if not base:
        return "https://api.openai.com/v1/chat/completions"
    base = base.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    if base.endswith("/v1"):
        return base + "/chat/completions"
    # 允许用户直接配置到 /v1/xxx 以外的兼容网关
    return base + "/v1/chat/completions"


def pick_ca_bundle(env: Dict[str, str]) -> Optional[str]:
    """
    为 OpenAI/兼容网关的 HTTPS 请求挑选 CA bundle。

    背景：固件 rootfs 常缺少系统 CA，导致 urllib 报：
      CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate

    策略：优先使用 env 显式配置，其次使用常见系统路径（兼容 /etc -> /tmp/etc）。
    """

    cand: List[str] = []
    for k in ("OPENAI_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"):
        v = (env.get(k) or "").strip()
        if v:
            cand.append(v)

    cand.extend(
        [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/ssl/cert.pem",
            "/tmp/etc/ssl/certs/ca-certificates.crt",
            "/tmp/etc/ssl/cert.pem",
        ]
    )

    for p in cand:
        try:
            if p and os.path.isfile(p):
                return p
        except Exception:
            continue
    return None


def detect_safe_root(run_dir: str) -> Optional[str]:
    """
    尽量判定“可以写入的固件 rootfs 根目录”，避免误写宿主机。

    返回：
      - "/" ：已在 chroot(rootfs) 内（固件根即 /）
      - "<abs>"：未 chroot，但规则目录位于 <abs>/rules_examples（可写入 <abs>）
      - None：无法确认在固件 rootfs，默认禁用写入类动作
    """

    # 1) 明确 marker：/.init_enable_core（约定：放在 rootfs 根）
    if os.path.isfile("/.init_enable_core"):
        return "/"

    # 2) 启发式：rootfs 根常见注入 qemu-arm 与 rules_examples
    if os.path.isfile("/qemu-arm") and os.path.isfile("/rules_examples/entry.lua"):
        return "/"

    # 3) 相对 cwd 的 marker（便于宿主机直接在 rootfs 目录运行 ./start.sh）
    if os.path.isfile("./.init_enable_core"):
        return os.path.abspath(".")
    if os.path.isfile("./rules_examples/entry.lua") and (os.path.isfile("./qemu-arm") or os.path.isfile("./usr/sbin/httpd")):
        return os.path.abspath(".")

    # 4) 从 run_dir 反推：.../<rootfs>/rules_examples/cache/ai_runs/<run_id>
    rd = os.path.abspath(run_dir or "")
    needle = os.sep + "rules_examples" + os.sep
    i = rd.find(needle)
    if i >= 0:
        root_guess = rd[:i] or "/"
        # 校验：root_guess 下应存在 rules_examples/entry.lua
        entry = os.path.join(root_guess, "rules_examples", "entry.lua")
        if os.path.isfile(entry):
            return root_guess

    return None


def _abspath(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def _within_root(path: str, safe_root: str) -> bool:
    if not safe_root:
        safe_root = "/"
    safe_root = _abspath(safe_root)
    path_abs = _abspath(path)
    if safe_root == "/":
        return True
    try:
        return os.path.commonpath([safe_root, path_abs]) == safe_root
    except Exception:
        return False


def _parse_mode(mode: Any, default: int) -> int:
    if mode is None:
        return default
    if isinstance(mode, int):
        return mode
    s = str(mode).strip()
    if not s:
        return default
    # 支持 "0755"/"644" 等八进制字符串
    try:
        if s.startswith("0"):
            return int(s, 8)
        # 仅当全为数字才按八进制解释；避免把 "493" 误当十进制
        if re.fullmatch(r"[0-7]+", s):
            return int(s, 8)
        return int(s, 10)
    except Exception:
        return default


def is_allowed_http_host(host: str) -> bool:
    """
    http_get 的目标 host 白名单。

    约束目标：
    - 默认禁止访问公网，避免将固件文件/上下文泄露到外部；
    - 允许访问本机/私网地址，用于验证固件 httpd 是否可用（127.0.0.1、容器内 172.17.*、常见 192.168.* 等）。
    """

    h = (host or "").strip().lower()
    if h in ("", "localhost", "127.0.0.1", "::1"):
        return True

    m = re.fullmatch(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", h)
    if not m:
        return False
    try:
        a, b, c, d = (int(x) for x in m.groups())
    except Exception:
        return False
    if not (0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 255 and 0 <= d <= 255):
        return False

    # 127.0.0.0/8
    if a == 127:
        return True
    # 10.0.0.0/8
    if a == 10:
        return True
    # 172.16.0.0/12
    if a == 172 and 16 <= b <= 31:
        return True
    # 192.168.0.0/16
    if a == 192 and b == 168:
        return True
    # 169.254.0.0/16（link-local）
    if a == 169 and b == 254:
        return True

    return False


class ActionRunner:
    """
    记录/执行 AI 干预动作（工具调用）。
    """

    def __init__(
        self,
        safe_root: Optional[str],
        allow_write: bool,
        allow_shell: bool,
        allow_net: bool,
        ip_bin: Optional[str] = None,
        assume_container: bool = False,
    ):
        self.safe_root = safe_root
        self.allow_write = allow_write
        self.allow_shell = allow_shell
        self.allow_net = allow_net
        self.ip_bin = (ip_bin or "").strip()
        self.assume_container = bool(assume_container)
        self.actions: List[Dict[str, Any]] = []
        self.mutations_applied = 0

    def _deny(self, tool: str, reason: str, args: Any = None) -> Dict[str, Any]:
        rec = {"tool": tool, "ok": False, "deny_reason": reason, "args": args}
        self.actions.append(rec)
        return rec

    def _record(self, tool: str, ok: bool, args: Any, result: Any, mutating: bool) -> Dict[str, Any]:
        rec = {"tool": tool, "ok": bool(ok), "args": args, "result": result}
        self.actions.append(rec)
        if ok and mutating:
            self.mutations_applied += 1
        return rec

    def _check_path(self, p: str) -> Tuple[bool, str]:
        if not self.safe_root:
            return False, "no_safe_root"
        if not _within_root(p, self.safe_root):
            return False, "path_outside_safe_root"
        return True, ""

    def fs_read_text(self, path: str, max_bytes: int = 64 * 1024) -> Dict[str, Any]:
        try:
            p = str(path)
            okp, why = self._check_path(p)
            if not okp:
                return self._deny("fs_read_text", why, {"path": path, "max_bytes": max_bytes})
            data = read_text_if_exists(p, max_bytes)
            truncated = False
            try:
                if os.path.isfile(p) and os.path.getsize(p) > max_bytes:
                    truncated = True
            except Exception:
                pass
            return self._record("fs_read_text", True, {"path": path, "max_bytes": max_bytes}, {"text": data, "truncated": truncated}, False)
        except Exception as ex:
            return self._record("fs_read_text", False, {"path": path, "max_bytes": max_bytes}, {"error": str(ex)}, False)

    def _is_container(self) -> bool:
        if self.assume_container:
            return True
        # docker / podman 常见 marker
        if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
            return True
        for cg in ("/proc/self/cgroup", "/proc/1/cgroup"):
            try:
                with open(cg, "r", encoding="utf-8", errors="replace") as f:
                    data = f.read()
                if any(x in data for x in ("docker", "containerd", "kubepods", "libpod")):
                    return True
            except Exception:
                continue
        return False

    def _find_ip(self) -> Optional[str]:
        cand: List[str] = []
        if self.ip_bin:
            cand.append(self.ip_bin)
        cand.extend(("/sfemu_tools/ip", "/usr/sbin/ip", "/sbin/ip", "/bin/ip"))
        for p in cand:
            if p and os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        w = shutil.which("ip")
        if w:
            return w
        return None

    def _run_cmd(self, argv: List[str], timeout_ms: int = 5000, max_output: int = 65536) -> Tuple[int, str]:
        p = subprocess.run(
            [str(x) for x in argv],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=max(0.1, float(timeout_ms) / 1000.0),
            check=False,
            text=True,
            errors="replace",
        )
        out = p.stdout or ""
        limit = int(max_output or 0) or 65536
        if len(out) > limit:
            out = out[:limit] + "\n...(truncated)\n"
        return int(p.returncode or 0), out

    def net_if_list(self, timeout_ms: int = 2000, max_output: int = 65536) -> Dict[str, Any]:
        if not self.allow_net:
            return self._deny("net_if_list", "net_disabled", {})
        if not self.safe_root:
            return self._deny("net_if_list", "no_safe_root", {})
        if not self._is_container():
            return self._deny("net_if_list", "not_in_container", {})
        ip = self._find_ip()
        if not ip:
            return self._record("net_if_list", False, {"timeout_ms": timeout_ms, "max_output": max_output}, {"error": "ip_not_found"}, False)
        try:
            rc, out = self._run_cmd([ip, "-j", "addr", "show"], timeout_ms=timeout_ms, max_output=max_output)
            if rc == 0:
                try:
                    data = json.loads(out)
                except Exception:
                    data = {"raw": out}
                return self._record("net_if_list", True, {"timeout_ms": timeout_ms, "max_output": max_output}, {"returncode": rc, "data": data}, False)
            return self._record("net_if_list", False, {"timeout_ms": timeout_ms, "max_output": max_output}, {"returncode": rc, "output": out}, False)
        except Exception as ex:
            return self._record("net_if_list", False, {"timeout_ms": timeout_ms, "max_output": max_output}, {"error": str(ex)}, False)

    def net_ensure_addr(self, iface: str, cidr: str, kind: str = "dummy", up: bool = True, timeout_ms: int = 5000) -> Dict[str, Any]:
        """
        保障网络环境（通用干预）：
        - 若 iface 不存在：创建（dummy/bridge）
        - 设为 up
        - 确保 iface 上存在 cidr（若已存在则跳过）
        """
        if not self.allow_net:
            return self._deny("net_ensure_addr", "net_disabled", {"iface": iface, "cidr": cidr, "kind": kind, "up": up})
        if not self.safe_root:
            return self._deny("net_ensure_addr", "no_safe_root", {"iface": iface, "cidr": cidr, "kind": kind, "up": up})
        if not self._is_container():
            return self._deny("net_ensure_addr", "not_in_container", {"iface": iface, "cidr": cidr, "kind": kind, "up": up})

        ifname = str(iface or "").strip()
        addr = str(cidr or "").strip()
        k = str(kind or "dummy").strip().lower()
        if k not in ("dummy", "bridge"):
            k = "dummy"

        if not ifname or not addr:
            return self._record("net_ensure_addr", False, {"iface": iface, "cidr": cidr, "kind": kind, "up": up}, {"error": "missing_iface_or_cidr"}, False)

        ip = self._find_ip()
        if not ip:
            return self._record("net_ensure_addr", False, {"iface": iface, "cidr": cidr, "kind": kind, "up": up}, {"error": "ip_not_found"}, False)

        mutated = False
        outputs: List[Dict[str, Any]] = []
        try:
            sys_net = f"/sys/class/net/{ifname}"
            if not os.path.isdir(sys_net):
                rc, out = self._run_cmd([ip, "link", "add", ifname, "type", k], timeout_ms=timeout_ms)
                outputs.append({"argv": [ip, "link", "add", ifname, "type", k], "returncode": rc, "output": out})
                if rc != 0:
                    return self._record("net_ensure_addr", False, {"iface": iface, "cidr": cidr, "kind": k, "up": up}, {"steps": outputs}, False)
                mutated = True

            if up:
                rc, out = self._run_cmd([ip, "link", "set", "dev", ifname, "up"], timeout_ms=timeout_ms)
                outputs.append({"argv": [ip, "link", "set", "dev", ifname, "up"], "returncode": rc, "output": out})
                if rc == 0:
                    mutated = True

            # 是否已存在该地址
            already = False
            rc, out = self._run_cmd([ip, "-j", "addr", "show", "dev", ifname], timeout_ms=timeout_ms)
            if rc == 0:
                try:
                    data = json.loads(out)
                    for item in data if isinstance(data, list) else []:
                        for a in item.get("addr_info") or []:
                            local = a.get("local")
                            prefixlen = a.get("prefixlen")
                            if local is None or prefixlen is None:
                                continue
                            if f"{local}/{prefixlen}" == addr:
                                already = True
                                break
                        if already:
                            break
                except Exception:
                    pass

            if not already:
                rc, out = self._run_cmd([ip, "addr", "add", addr, "dev", ifname], timeout_ms=timeout_ms)
                outputs.append({"argv": [ip, "addr", "add", addr, "dev", ifname], "returncode": rc, "output": out})
                if rc == 0:
                    mutated = True
            else:
                outputs.append({"note": "addr_exists", "addr": addr})

            return self._record("net_ensure_addr", True, {"iface": ifname, "cidr": addr, "kind": k, "up": up}, {"steps": outputs}, mutated)
        except Exception as ex:
            return self._record("net_ensure_addr", False, {"iface": iface, "cidr": cidr, "kind": kind, "up": up}, {"error": str(ex), "steps": outputs}, mutated)

    def fs_read_bytes_b64(self, path: str, max_bytes: int = 4096, offset: int = 0) -> Dict[str, Any]:
        try:
            p = str(path)
            okp, why = self._check_path(p)
            if not okp:
                return self._deny("fs_read_bytes_b64", why, {"path": path, "max_bytes": max_bytes, "offset": offset})
            offset_i = int(offset or 0)
            max_i = int(max_bytes or 0)
            if max_i <= 0:
                max_i = 1
            with open(p, "rb") as f:
                if offset_i > 0:
                    f.seek(offset_i)
                data = f.read(max_i)
            b64 = base64.b64encode(data).decode("ascii")
            more = False
            try:
                if os.path.isfile(p) and os.path.getsize(p) > offset_i + len(data):
                    more = True
            except Exception:
                pass
            return self._record(
                "fs_read_bytes_b64",
                True,
                {"path": path, "max_bytes": max_bytes, "offset": offset},
                {"b64": b64, "n": len(data), "more": more},
                False,
            )
        except Exception as ex:
            return self._record("fs_read_bytes_b64", False, {"path": path, "max_bytes": max_bytes, "offset": offset}, {"error": str(ex)}, False)

    def fs_listdir(self, path: str, max_entries: int = 200) -> Dict[str, Any]:
        try:
            p = str(path)
            okp, why = self._check_path(p)
            if not okp:
                return self._deny("fs_listdir", why, {"path": path, "max_entries": max_entries})
            items = []
            for name in sorted(os.listdir(p))[: int(max_entries or 0) or 200]:
                items.append(name)
            return self._record("fs_listdir", True, {"path": path, "max_entries": max_entries}, {"entries": items}, False)
        except Exception as ex:
            return self._record("fs_listdir", False, {"path": path, "max_entries": max_entries}, {"error": str(ex)}, False)

    def fs_glob(self, pattern: str, max_results: int = 200) -> Dict[str, Any]:
        try:
            pat = str(pattern)
            # glob 本身可能跨目录，这里只在结果集层面做 safe_root 校验
            results = sorted(glob.glob(pat, recursive=True))
            limit = int(max_results or 0) or 200
            safe = []
            for p in results:
                if self.safe_root and _within_root(p, self.safe_root):
                    safe.append(p)
                if len(safe) >= limit:
                    break
            return self._record("fs_glob", True, {"pattern": pattern, "max_results": max_results}, {"paths": safe, "total": len(results)}, False)
        except Exception as ex:
            return self._record("fs_glob", False, {"pattern": pattern, "max_results": max_results}, {"error": str(ex)}, False)

    def fs_mkdir_p(self, path: str, mode: Any = None) -> Dict[str, Any]:
        if not self.allow_write:
            return self._deny("fs_mkdir_p", "write_disabled", {"path": path, "mode": mode})
        try:
            p = str(path)
            okp, why = self._check_path(p)
            if not okp:
                return self._deny("fs_mkdir_p", why, {"path": path, "mode": mode})
            m = _parse_mode(mode, 0o755)
            os.makedirs(p, exist_ok=True)
            try:
                os.chmod(p, m)
            except Exception:
                pass
            return self._record("fs_mkdir_p", True, {"path": path, "mode": mode}, {"created": True}, True)
        except Exception as ex:
            return self._record("fs_mkdir_p", False, {"path": path, "mode": mode}, {"error": str(ex)}, True)

    def fs_write_text(self, path: str, content: str, mode: Any = None, mkdirs: bool = True, overwrite: bool = True) -> Dict[str, Any]:
        if not self.allow_write:
            return self._deny("fs_write_text", "write_disabled", {"path": path})
        try:
            p = str(path)
            okp, why = self._check_path(p)
            if not okp:
                return self._deny("fs_write_text", why, {"path": path})
            if mkdirs:
                os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
            if (not overwrite) and os.path.exists(p):
                return self._record("fs_write_text", True, {"path": path, "mode": mode, "mkdirs": mkdirs, "overwrite": overwrite}, {"skipped": True, "reason": "exists"}, False)
            data = str(content or "")
            with open(p, "w", encoding="utf-8", errors="replace") as f:
                f.write(data)
            if mode is not None:
                try:
                    os.chmod(p, _parse_mode(mode, 0o644))
                except Exception:
                    pass
            return self._record("fs_write_text", True, {"path": path, "mode": mode, "mkdirs": mkdirs, "overwrite": overwrite}, {"n": len(data)}, True)
        except Exception as ex:
            return self._record("fs_write_text", False, {"path": path, "mode": mode, "mkdirs": mkdirs, "overwrite": overwrite}, {"error": str(ex)}, True)

    def fs_symlink(self, target: str, link_path: str, force: bool = True) -> Dict[str, Any]:
        if not self.allow_write:
            return self._deny("fs_symlink", "write_disabled", {"target": target, "link_path": link_path})
        try:
            lp = str(link_path)
            okp, why = self._check_path(lp)
            if not okp:
                return self._deny("fs_symlink", why, {"target": target, "link_path": link_path})
            if force and os.path.lexists(lp):
                try:
                    if os.path.isdir(lp) and not os.path.islink(lp):
                        return self._record("fs_symlink", False, {"target": target, "link_path": link_path, "force": force}, {"error": "link_path_is_dir"}, True)
                    os.unlink(lp)
                except Exception as ex:
                    return self._record("fs_symlink", False, {"target": target, "link_path": link_path, "force": force}, {"error": str(ex)}, True)
            os.makedirs(os.path.dirname(lp) or ".", exist_ok=True)
            os.symlink(str(target), lp)
            return self._record("fs_symlink", True, {"target": target, "link_path": link_path, "force": force}, {"created": True}, True)
        except Exception as ex:
            return self._record("fs_symlink", False, {"target": target, "link_path": link_path, "force": force}, {"error": str(ex)}, True)

    def fs_copy(self, src: str, dst: str, overwrite: bool = True) -> Dict[str, Any]:
        if not self.allow_write:
            return self._deny("fs_copy", "write_disabled", {"src": src, "dst": dst})
        try:
            s = str(src)
            d = str(dst)
            oks, why_s = self._check_path(s)
            if not oks:
                return self._deny("fs_copy", why_s, {"src": src, "dst": dst})
            okd, why = self._check_path(d)
            if not okd:
                return self._deny("fs_copy", why, {"src": src, "dst": dst})
            if (not overwrite) and os.path.exists(d):
                return self._record("fs_copy", True, {"src": src, "dst": dst, "overwrite": overwrite}, {"skipped": True, "reason": "exists"}, False)
            os.makedirs(os.path.dirname(d) or ".", exist_ok=True)
            shutil.copy2(s, d)
            return self._record("fs_copy", True, {"src": src, "dst": dst, "overwrite": overwrite}, {"copied": True}, True)
        except Exception as ex:
            return self._record("fs_copy", False, {"src": src, "dst": dst, "overwrite": overwrite}, {"error": str(ex)}, True)

    def http_get(self, url: str, timeout_ms: int = 2000, max_bytes: int = 8192) -> Dict[str, Any]:
        try:
            u = str(url)
            # 出于安全：默认仅允许访问本机/私网（用于验证固件 http 服务），禁止访问公网。
            pu = urllib.parse.urlparse(u)
            host = (pu.hostname or "").lower()
            if not is_allowed_http_host(host):
                return self._deny("http_get", "host_not_allowed", {"url": url})
            req = urllib.request.Request(u, method="GET", headers={"User-Agent": "sfemu-ai/1.0"})
            with urllib.request.urlopen(req, timeout=max(0.1, float(timeout_ms) / 1000.0)) as resp:
                data = resp.read(int(max_bytes or 0) or 8192)
                headers = dict(resp.headers.items())
                return self._record(
                    "http_get",
                    True,
                    {"url": url, "timeout_ms": timeout_ms, "max_bytes": max_bytes},
                    {"status": getattr(resp, "status", None), "headers": headers, "body_snippet": data.decode("utf-8", errors="replace")},
                    False,
                )
        except Exception as ex:
            return self._record("http_get", False, {"url": url, "timeout_ms": timeout_ms, "max_bytes": max_bytes}, {"error": str(ex)}, False)

    def shell_run(self, argv: List[str], timeout_ms: int = 5000, max_output: int = 65536) -> Dict[str, Any]:
        if not self.allow_shell:
            return self._deny("shell_run", "shell_disabled", {"argv": argv})
        if not isinstance(argv, list) or not argv:
            return self._record("shell_run", False, {"argv": argv}, {"error": "argv_empty"}, False)
        try:
            # 仅允许白名单命令（可按需扩展）
            allow = {
                "ls", "cat", "head", "tail", "stat", "file",
                "mkdir", "ln", "cp", "mv", "rm",
                "grep", "sed", "awk", "find",
                "ps", "ss", "netstat", "ip", "ifconfig", "route",
                "curl", "wget",
                "openssl",
            }
            cmd = str(argv[0])
            base = os.path.basename(cmd)
            if base not in allow:
                return self._deny("shell_run", "cmd_not_allowed", {"argv": argv})
            rc, out = self._run_cmd([str(x) for x in argv], timeout_ms=timeout_ms, max_output=max_output)
            mut = False
            ro = {"ls", "cat", "head", "tail", "stat", "file", "grep", "sed", "awk", "find", "ps", "ss", "netstat", "curl", "wget"}
            wr = {"mkdir", "ln", "cp", "mv", "rm", "ip", "ifconfig", "route", "openssl"}
            if base in wr:
                if base == "ip":
                    # ip 的 show 类命令本身无副作用；仅当出现 add/del/set/flush/replace 才计为变更
                    mut = any(str(x) in ("add", "del", "set", "flush", "replace") for x in argv[1:6])
                elif base == "ifconfig":
                    mut = len(argv) >= 3
                elif base == "route":
                    mut = any(str(x) in ("add", "del", "change", "replace") for x in argv[1:6])
                else:
                    mut = True
            elif base in ro:
                mut = False
            else:
                # 默认保守：不计入变更（避免模型仅做观测就触发 re-exec）
                mut = False
            return self._record("shell_run", True, {"argv": argv, "timeout_ms": timeout_ms, "max_output": max_output}, {"returncode": rc, "output": out}, mut)
        except Exception as ex:
            return self._record("shell_run", False, {"argv": argv, "timeout_ms": timeout_ms, "max_output": max_output}, {"error": str(ex)}, True)

    def run_action(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        tool = str(tool or "")
        args = args or {}
        if tool == "fs_read_text":
            return self.fs_read_text(args.get("path", ""), int(args.get("max_bytes") or 64 * 1024))
        if tool == "fs_read_bytes_b64":
            return self.fs_read_bytes_b64(args.get("path", ""), int(args.get("max_bytes") or 4096), int(args.get("offset") or 0))
        if tool == "fs_listdir":
            return self.fs_listdir(args.get("path", ""), int(args.get("max_entries") or 200))
        if tool == "fs_glob":
            return self.fs_glob(args.get("pattern", ""), int(args.get("max_results") or 200))
        if tool == "fs_mkdir_p":
            return self.fs_mkdir_p(args.get("path", ""), args.get("mode"))
        if tool == "fs_write_text":
            return self.fs_write_text(
                args.get("path", ""),
                args.get("content", ""),
                mode=args.get("mode"),
                mkdirs=bool(args.get("mkdirs", True)),
                overwrite=bool(args.get("overwrite", True)),
            )
        if tool == "fs_symlink":
            return self.fs_symlink(args.get("target", ""), args.get("link_path", ""), force=bool(args.get("force", True)))
        if tool == "fs_copy":
            return self.fs_copy(args.get("src", ""), args.get("dst", ""), overwrite=bool(args.get("overwrite", True)))
        if tool == "http_get":
            return self.http_get(args.get("url", ""), int(args.get("timeout_ms") or 2000), int(args.get("max_bytes") or 8192))
        if tool == "net_if_list":
            return self.net_if_list(int(args.get("timeout_ms") or 2000), int(args.get("max_output") or 65536))
        if tool == "net_ensure_addr":
            return self.net_ensure_addr(
                args.get("iface", ""),
                args.get("cidr", ""),
                kind=str(args.get("kind") or "dummy"),
                up=bool(args.get("up", True)),
                timeout_ms=int(args.get("timeout_ms") or 5000),
            )
        if tool == "shell_run":
            return self.shell_run(args.get("argv", []), int(args.get("timeout_ms") or 5000), int(args.get("max_output") or 65536))
        return self._record("unknown_tool", False, {"tool": tool, "args": args}, {"error": "unknown_tool"}, False)


def build_tools_spec(env: Dict[str, str], allow_write: bool, allow_shell: bool, allow_net: bool) -> List[Dict[str, Any]]:
    """
    OpenAI tools 规范（Chat Completions）。
    """
    tools: List[Dict[str, Any]] = []

    def add(name: str, desc: str, props: Dict[str, Any], required: List[str]) -> None:
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": desc,
                    "parameters": {
                        "type": "object",
                        "properties": props,
                        "required": required,
                        "additionalProperties": False,
                    },
                },
            }
        )

    add(
        "fs_read_text",
        "读取固件 rootfs 内的文本文件（UTF-8 兜底替换），用于定位问题。只读。",
        {"path": {"type": "string"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576}},
        ["path"],
    )
    add(
        "fs_read_bytes_b64",
        "读取固件 rootfs 内的二进制文件并以 base64 返回（用于小体积证据采集）。只读。",
        {
            "path": {"type": "string"},
            "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576},
            "offset": {"type": "integer", "minimum": 0, "maximum": 1073741824},
        },
        ["path"],
    )
    add(
        "fs_listdir",
        "列出目录内容（用于定位 webroot/脚本/证书等）。只读。",
        {"path": {"type": "string"}, "max_entries": {"type": "integer", "minimum": 1, "maximum": 2000}},
        ["path"],
    )
    add(
        "fs_glob",
        "使用 glob(pattern) 查找文件（支持 ** 递归），结果会被 safe_root 过滤。只读。",
        {"pattern": {"type": "string"}, "max_results": {"type": "integer", "minimum": 1, "maximum": 2000}},
        ["pattern"],
    )

    if allow_write:
        add(
            "fs_mkdir_p",
            "递归创建目录（等价 mkdir -p）。写入。",
            {"path": {"type": "string"}, "mode": {"type": ["integer", "string", "null"]}},
            ["path"],
        )
        add(
            "fs_write_text",
            "写入文本文件（可选创建父目录）。写入。",
            {
                "path": {"type": "string"},
                "content": {"type": "string"},
                "mode": {"type": ["integer", "string", "null"]},
                "mkdirs": {"type": "boolean"},
                "overwrite": {"type": "boolean"},
            },
            ["path", "content"],
        )
        add(
            "fs_symlink",
            "创建软链接（可 force 覆盖）。写入。",
            {"target": {"type": "string"}, "link_path": {"type": "string"}, "force": {"type": "boolean"}},
            ["target", "link_path"],
        )
        add(
            "fs_copy",
            "拷贝文件（可 overwrite 覆盖）。写入。",
            {"src": {"type": "string"}, "dst": {"type": "string"}, "overwrite": {"type": "boolean"}},
            ["src", "dst"],
        )

    add(
        "http_get",
        "对本机/私网地址发起 HTTP GET（用于验证 httpd 是否有回包/是否 404）。只读；禁止访问公网。",
        {"url": {"type": "string"}, "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 10000}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576}},
        ["url"],
    )

    if allow_net:
        add(
            "net_if_list",
            "查看当前网络接口与地址（优先使用 ip -j）。只读。",
            {"timeout_ms": {"type": "integer", "minimum": 100, "maximum": 60000}, "max_output": {"type": "integer", "minimum": 1, "maximum": 1048576}},
            [],
        )
        add(
            "net_ensure_addr",
            "通用网络补齐：确保 iface 存在（必要时创建 dummy/bridge）、置 up，并确保其上存在指定 IPv4 CIDR（如 192.168.1.1/24）。写入/有副作用。",
            {
                "iface": {"type": "string"},
                "cidr": {"type": "string"},
                "kind": {"type": "string", "enum": ["dummy", "bridge"]},
                "up": {"type": "boolean"},
                "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 60000},
            },
            ["iface", "cidr"],
        )

    if allow_shell:
        add(
            "shell_run",
            "在当前环境执行白名单命令（默认关闭，需显式启用）。写入/有副作用，谨慎使用。",
            {
                "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 64},
                "timeout_ms": {"type": "integer", "minimum": 100, "maximum": 60000},
                "max_output": {"type": "integer", "minimum": 1, "maximum": 1048576},
            },
            ["argv"],
        )

    return tools


def read_text_if_exists(path: str, max_bytes: int = 64 * 1024) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def hexdump(data: bytes, max_bytes: int = 256) -> str:
    data = data[:max_bytes]
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        out.append(f"{i:04x}: {hexs:<47}  {asc}")
    if len(data) >= max_bytes:
        out.append(f"...(trunc {max_bytes} bytes)")
    return "\n".join(out)


def build_prompt(snapshot: Dict[str, Any], run_dir: str, env: Dict[str, str]) -> Tuple[str, str]:
    """
    返回 (system_prompt, user_prompt)
    """
    reason = snapshot.get("reason")
    trig = snapshot.get("trigger") or {}
    recent = snapshot.get("recent_syscalls") or []
    regs_txt = read_text_if_exists(os.path.join(run_dir, "regs.txt"), 64 * 1024)
    bt_txt = read_text_if_exists(os.path.join(run_dir, "backtrace.txt"), 64 * 1024)
    diagnosis = read_text_if_exists(os.path.join(run_dir, "diagnosis.md"), 64 * 1024)

    # 尽量把“内存证据”做成可读信息（读取 memory/*.bin 的前 256B 十六进制）
    mem_dir = os.path.join(run_dir, "memory")
    mem_blobs = []
    try:
        if os.path.isdir(mem_dir):
            for name in sorted(os.listdir(mem_dir)):
                if not name.endswith(".bin"):
                    continue
                p = os.path.join(mem_dir, name)
                try:
                    with open(p, "rb") as f:
                        blob = f.read(256)
                    mem_blobs.append({"file": name, "hexdump": hexdump(blob, 256)})
                except Exception:
                    continue
    except Exception:
        pass

    # 控制 recent 长度，避免 prompt 过大
    recent_tail = recent[-64:] if isinstance(recent, list) else []

    system_prompt = (
        "你是一个资深的二进制仿真/系统调用兼容性工程师。\n"
        "推理强度（Reasoning effort）：Extra high。\n"
        "我会给你一份仿真失败时的上下文快照（寄存器、调用栈、近期 syscall 序列、内存证据）。\n"
        "你的任务是：优先用“最小环境干预（actions/tools）”让固件继续运行并把 http 服务跑起来；\n"
        "只有当无法通过环境补齐解决时，才生成最小、可回滚、尽量精确命中的 Lua syscall 规则。\n"
        "\n"
        "规则接口约定：\n"
        "- 文件位置：syscall/<name>.lua\n"
        "- 必须定义：function do_syscall(num, arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8)\n"
        "- 返回：(action, ret)\n"
        "  - action=0：不拦截，继续执行真实 syscall\n"
        "  - action=1：拦截，直接返回 ret（可为负 errno，例如 -2 表示 -ENOENT）\n"
        "\n"
        "可用辅助函数（部分）：c_log/c_read_string/c_read_bytes/c_write_bytes 等。\n"
        "\n"
        "输出要求：只输出一个 JSON（不要 Markdown/代码块），格式固定如下：\n"
        "{\n"
        "  \"fix\": { \"syscall/<name>.lua\": \"<lua source>\" },\n"
        "  \"observe\": { \"syscall/<name>.lua\": \"<lua source>\" },\n"
        "  \"explain\": \"简要说明为什么这么改，以及风险/回滚点\",\n"
        "  \"actions\": [\n"
        "    {\"tool\": \"fs_mkdir_p\", \"args\": {\"path\": \"/var/run\", \"mode\": \"0755\"}},\n"
        "    {\"tool\": \"fs_write_text\", \"args\": {\"path\": \"/etc/TZ\", \"content\": \"UTC\\n\", \"overwrite\": false}}\n"
        "  ]\n"
        "}\n"
        "\n"
        "actions 说明：\n"
        "- 可选字段，用于做“轻量 filesystem 干预”（补目录/补文件/建软链/拷贝等），以减少为每个固件手写规则。\n"
        "- 若 reason 是 sleep_loop/deadloop：优先检查网络与 webroot：\n"
        "  1) 用 net_if_list 查看接口；若缺 br0 或缺 192.168.1.1/24，可用 net_ensure_addr 补齐（先 bridge，失败再 dummy，或改用 eth0）。\n"
        "  2) 用 http_get 验证 127.0.0.1/192.168.1.1/172.17.* 是否有回包。\n"
        "- 若当前执行器支持 tools/tool_calls，你也可以直接调用工具来读取/修改 rootfs，并在最后输出 JSON。\n"
        "- 只做最小必要修改；尽量幂等（重复执行不会破坏环境）。\n"
        "\n"
        "注意：\n"
        "- 不要硬编码绝对路径；尽量用参数+少量上下文特征（如 sockaddr 内容/固定 fd/关键参数）精确命中。\n"
        "- 如果触发点是 exit/exit_group：优先修复导致退出的根因；必要时可生成“只拦截一次”的 exit/exit_group 规则用于继续运行。\n"
    )

    user_prompt = (
        "## 触发原因\n"
        f"- reason: {reason!r}\n"
        f"- trigger: syscall={trig.get('syscall_name')!r} num={trig.get('syscall_num')!r} "
        f"args={trig.get('args')!r} ret={trig.get('ret')!r} intercepted={trig.get('intercepted')!r}\n"
        "\n"
        "## 近期 syscall（tail）\n"
        + "\n".join(
            f"- seq={c.get('seq')} {c.get('name')}({c.get('num')}) args={c.get('args')} ret={c.get('ret')} intercepted={c.get('intercepted')}"
            for c in recent_tail
            if isinstance(c, dict)
        )
        + "\n\n"
        "## 调用栈（解析结果）\n"
        + bt_txt
        + "\n"
        "## 寄存器（节选/文本）\n"
        + regs_txt
        + "\n"
        "## 诊断报告（启发式）\n"
        + diagnosis
    )

    if mem_blobs:
        user_prompt += "\n## 内存证据（二进制 hexdump，最多 256B/项）\n"
        for item in mem_blobs[:16]:
            user_prompt += f"\n### {item['file']}\n{item['hexdump']}\n"

    # 可选：把调用栈对应的伪 C 一并放入 prompt（默认开启，但会严格截断避免 prompt 过大）
    include_pseudo = str_bool(env.get("SFEMU_AI_MCP_INCLUDE_PSEUDOCODE") or env.get("SFEMU_AI_MCP_PSEUDOCODE"), True)
    pseudo_max_frames = clamp_int(env.get("SFEMU_AI_MCP_PSEUDOCODE_FRAMES"), 0, 256, 4)
    pseudo_max_total = clamp_int(env.get("SFEMU_AI_MCP_PSEUDOCODE_MAX_BYTES"), 0, 1 << 20, 32 * 1024)
    pseudo_max_file = clamp_int(env.get("SFEMU_AI_MCP_PSEUDOCODE_FILE_BYTES"), 0, 1 << 20, 8 * 1024)

    if include_pseudo and pseudo_max_frames > 0 and pseudo_max_total > 0 and pseudo_max_file > 0:
        bt = snapshot.get("backtrace") or {}
        pseudo_index = (bt.get("pseudocode_index") if isinstance(bt, dict) else None) or []
        frames = (bt.get("frames") if isinstance(bt, dict) else None) or []

        frame_map: Dict[int, Dict[str, Any]] = {}
        if isinstance(frames, list):
            for f in frames:
                if not isinstance(f, dict):
                    continue
                idx = f.get("idx")
                if isinstance(idx, int):
                    frame_map[idx] = f

        def utf8_len(s: str) -> int:
            return len((s or "").encode("utf-8", errors="replace"))

        def resolve_pseudocode_path(p: str) -> str:
            # 1) 原样（绝对路径或相对路径，按当前 cwd 解析）
            cand = os.path.abspath(p)
            if os.path.isfile(cand):
                return cand
            # 2) 兜底：只用 basename，强制从 run_dir/pseudocode 取
            cand2 = os.path.abspath(os.path.join(run_dir, "pseudocode", os.path.basename(p)))
            if os.path.isfile(cand2):
                return cand2
            return ""

        picked = []
        total_bytes = 0
        if isinstance(pseudo_index, list):
            for it in pseudo_index:
                if len(picked) >= pseudo_max_frames:
                    break
                if total_bytes >= pseudo_max_total:
                    break
                if not isinstance(it, dict):
                    continue
                fno = it.get("frame")
                addr_hex = it.get("addr_hex")
                p = it.get("file")
                if not isinstance(p, str) or not p.strip():
                    continue
                abs_p = resolve_pseudocode_path(p)
                if not abs_p:
                    continue
                text = read_text_if_exists(abs_p, pseudo_max_file)
                if not text.strip():
                    continue

                # 总量截断：避免 prompt 过大
                remain = pseudo_max_total - total_bytes
                mcp_truncated = False
                if remain <= 0:
                    break
                if utf8_len(text) > remain:
                    raw = text.encode("utf-8", errors="replace")[:remain]
                    text = raw.decode("utf-8", errors="replace")
                    mcp_truncated = True

                total_bytes += utf8_len(text)

                head = []
                head.append(f"frame={fno} addr={addr_hex}")
                fi = frame_map.get(fno) if isinstance(fno, int) else None
                if fi:
                    mn = fi.get("module_name")
                    fn = fi.get("func_name")
                    if mn or fn:
                        head.append(f"{mn}::{fn}")
                    pcf = fi.get("pseudocode_file")
                    if pcf:
                        head.append(f"pseudo_c_file={pcf}")

                note = []
                if it.get("truncated") is True:
                    note.append("sfanalysis_truncated=1")
                if mcp_truncated:
                    note.append("mcp_truncated=1")

                header = " ".join(str(x) for x in head if x is not None and str(x) != "")
                if note:
                    header += " [" + ", ".join(note) + "]"

                picked.append((header, text))

        if picked:
            user_prompt += "\n\n## 伪C（调用栈对应，节选）\n"
            user_prompt += f"(max_frames={pseudo_max_frames} max_total_bytes={pseudo_max_total} max_file_bytes={pseudo_max_file})\n"
            for header, text in picked:
                user_prompt += f"\n### {header}\n{text}\n"

    return system_prompt, user_prompt


def _openai_do_request(base_url: str, api_key: str, payload: Dict[str, Any], env: Dict[str, str]) -> bytes:
    req = urllib.request.Request(
        base_url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    ctx = None
    cafile = None
    try:
        cafile = pick_ca_bundle(env)
    except Exception:
        cafile = None
    try:
        if cafile:
            ctx = ssl.create_default_context(cafile=cafile)
        else:
            ctx = ssl.create_default_context()
    except Exception:
        ctx = None

    with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
        return resp.read()


def call_openai_chat_raw(env: Dict[str, str], messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    api_key = env.get("OPENAI_API_KEY") or env.get("OPENAI_KEY") or ""
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY 未设置")

    model = env.get("OPENAI_MODEL") or "gpt-4o-mini"
    base_url = normalize_chat_completions_url(env.get("OPENAI_BASE_URL") or env.get("OPENAI_BASEURL") or "")

    payload: Dict[str, Any] = {
        "model": model,
        "temperature": 0,
        "messages": messages,
    }

    # 尽量启用 JSON mode（OpenAI/Gateway 常支持 response_format=json_object），强制模型输出 JSON，避免解析失败。
    # 兼容性：若网关不支持该字段，回退到普通模式。
    json_mode = env.get("OPENAI_JSON_MODE") or env.get("SFEMU_AI_JSON_MODE")
    json_mode_on = json_mode is None or str(json_mode).strip().lower() in ("1", "true", "yes", "y", "on")
    if tools:
        payload["tools"] = tools
        # 默认 auto：让模型自行决定是否调用工具
        payload["tool_choice"] = "auto"

    # 兼容策略：依次尝试
    # 1) tools + response_format（若开启 JSON mode）
    # 2) tools（不带 response_format）
    # 3) 无 tools（带 response_format）
    # 4) 无 tools（不带 response_format）
    attempts: List[Dict[str, Any]] = []
    if json_mode_on:
        p1 = dict(payload)
        p1["response_format"] = {"type": "json_object"}
        attempts.append(p1)
    attempts.append(dict(payload))

    if tools:
        # 无 tools 的尝试（保底）
        payload_no_tools = dict(payload)
        payload_no_tools.pop("tools", None)
        payload_no_tools.pop("tool_choice", None)
        if json_mode_on:
            p3 = dict(payload_no_tools)
            p3["response_format"] = {"type": "json_object"}
            attempts.append(p3)
        attempts.append(payload_no_tools)

    last_http_err: Optional[urllib.error.HTTPError] = None
    last_body = ""
    for p in attempts:
        try:
            data = _openai_do_request(base_url, api_key, p, env)
            return json.loads(data.decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as ex:
            last_http_err = ex
            try:
                last_body = ex.read().decode("utf-8", errors="replace") if hasattr(ex, "read") else ""
            except Exception:
                last_body = ""
            # 常见兼容失败：unknown field/extra inputs/response_format not permitted 等
            if ex.code in (400, 404):
                continue
            raise

    if last_http_err is not None:
        raise RuntimeError(f"OpenAI API HTTPError: code={last_http_err.code} msg={last_http_err.msg} body={last_body[:2000]}")
    raise RuntimeError("OpenAI API 调用失败：无可用尝试（无 HTTPError）")


def extract_message(resp_obj: Dict[str, Any]) -> Dict[str, Any]:
    msg = ((resp_obj.get("choices") or [{}])[0].get("message") or {})  # type: ignore[union-attr]
    if not isinstance(msg, dict):
        return {}
    return msg


def run_openai_agent(env: Dict[str, str], system_prompt: str, user_prompt: str, runner: ActionRunner, tools: Optional[List[Dict[str, Any]]]) -> str:
    """
    支持 tool_calls 的多轮对话：模型可读取/修改 rootfs，再输出最终 JSON。
    """
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    max_steps = clamp_int(env.get("SFEMU_AI_MCP_MAX_TOOL_STEPS"), 0, 64, 8)
    # tools 为空则退化为单轮
    if not tools or max_steps == 0:
        resp = call_openai_chat_raw(env, messages, tools=None)
        msg = extract_message(resp)
        return str(msg.get("content") or "")

    for _ in range(max_steps):
        resp = call_openai_chat_raw(env, messages, tools=tools)
        msg = extract_message(resp)

        tool_calls = msg.get("tool_calls")
        if isinstance(tool_calls, list) and tool_calls:
            # 先把 assistant/tool_calls 消息放回历史
            messages.append(msg)
            for tc in tool_calls:
                try:
                    if not isinstance(tc, dict):
                        continue
                    tc_id = tc.get("id") or ""
                    fn = tc.get("function") or {}
                    name = (fn.get("name") if isinstance(fn, dict) else None) or ""
                    arg_str = (fn.get("arguments") if isinstance(fn, dict) else None) or "{}"
                    try:
                        args = json.loads(arg_str) if isinstance(arg_str, str) and arg_str.strip() else {}
                    except Exception:
                        args = {"_raw": str(arg_str)}
                    result = runner.run_action(str(name), args if isinstance(args, dict) else {"_": args})
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": str(tc_id),
                            "content": json.dumps(result, ensure_ascii=False),
                        }
                    )
                except Exception as ex:
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": str((tc or {}).get("id") or ""),
                            "content": json.dumps({"ok": False, "error": str(ex)}, ensure_ascii=False),
                        }
                    )
            continue

        # 兼容旧式 function_call（极少数网关）
        fn_call = msg.get("function_call")
        if isinstance(fn_call, dict) and fn_call.get("name"):
            messages.append(msg)
            name = str(fn_call.get("name") or "")
            arg_str = str(fn_call.get("arguments") or "{}")
            try:
                args = json.loads(arg_str) if arg_str.strip() else {}
            except Exception:
                args = {"_raw": arg_str}
            result = runner.run_action(name, args if isinstance(args, dict) else {"_": args})
            messages.append({"role": "function", "name": name, "content": json.dumps(result, ensure_ascii=False)})
            continue

        # 无工具调用：视为最终回复
        return str(msg.get("content") or "")

    # 超过最大步数：返回最后一条内容（可能为空）
    return str((messages[-1] or {}).get("content") or "")

    obj = json.loads(data.decode("utf-8", errors="replace"))
    content = (
        ((obj.get("choices") or [{}])[0].get("message") or {}).get("content")  # type: ignore[union-attr]
        or ""
    )
    return str(content)


def extract_first_json(text: str) -> Dict[str, Any]:
    t = (text or "").strip()
    if not t:
        raise RuntimeError("LLM 返回空内容")

    # 1) 直接尝试：理想情况为纯 JSON
    try:
        obj = json.loads(t)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    # 2) 容错：允许前后缀/说明文本，尝试从任意 '{' 开始 raw_decode
    decoder = json.JSONDecoder()
    for i, ch in enumerate(t):
        if ch != "{":
            continue
        try:
            obj, _end = decoder.raw_decode(t[i:])
        except Exception:
            continue
        if isinstance(obj, dict):
            return obj

    raise RuntimeError("未找到可解析的 JSON 对象")


def pick_last_error_syscall(snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    recent = snapshot.get("recent_syscalls")
    if not isinstance(recent, list):
        return None
    for it in reversed(recent):
        if not isinstance(it, dict):
            continue
        ret = it.get("ret")
        if isinstance(ret, int) and ret < 0:
            return it
    return None


def decode_unix_sock_path(sockaddr: bytes) -> Optional[str]:
    if not sockaddr or len(sockaddr) < 4:
        return None
    family = sockaddr[0] | (sockaddr[1] << 8)
    if family != 1:  # AF_UNIX
        return None
    path_bytes = sockaddr[2:]
    nul = path_bytes.find(b"\x00")
    if nul >= 0:
        path_bytes = path_bytes[:nul]
    # abstract namespace: leading NUL
    if path_bytes.startswith(b"\x00"):
        return None
    try:
        return path_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None


def safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def build_fallback_rules(snapshot: Dict[str, Any], run_dir: str) -> Optional[Dict[str, Any]]:
    """
    当 API 不可用或 LLM 未按协议输出 JSON 时的兜底：基于快照启发式生成“最小可用”修复规则。

    当前覆盖的高频场景：
    - /dev/log（syslog）缺失导致 connect() -> -ENOENT -> exit_group
    - AF_NETLINK + 特定协议号不受支持导致 socket() -> -EPROTONOSUPPORT(-93)
    """
    last_err = pick_last_error_syscall(snapshot)
    if not last_err:
        return None

    name = last_err.get("name")
    # 场景 2：AF_NETLINK 特定协议号不受支持 -> socket() = -EPROTONOSUPPORT(-93)
    if name == "socket":
        ret = last_err.get("ret")
        if ret != -93:
            return None
        args = last_err.get("args")
        if not isinstance(args, list) or len(args) < 3:
            return None
        domain = safe_int(args[0], -1)
        stype = safe_int(args[1], -1)
        proto = safe_int(args[2], -1)
        # 仅对明确的 (AF_NETLINK=16, SOCK_RAW=3, proto=31) 做保守映射
        if domain != 16 or stype != 3 or proto != 31:
            return None

        socket_lua = """-- sfemu:transient=0
-- 自动修复规则：AF_NETLINK 未知协议兼容（socket）
-- 说明：
-- - 部分固件会创建 netlink socket 使用特定协议号（在宿主机内核上可能不受支持），导致 socket() 返回 -EPROTONOSUPPORT(-93)。
-- - 该失败常引发固件反复打印 netlink 初始化失败并退出。
-- 处理策略（保守）：仅在精确匹配 (AF_NETLINK=16, SOCK_RAW=3, proto=31) 时命中，
-- 将 proto 映射到 NETLINK_ROUTE(0) 创建真实 fd，让后续 sendmsg/recvmsg 走原始内核路径。

local AF_NETLINK = 16
local SOCK_RAW = 3
local BAD_PROTO = 31
local FALLBACK_PROTO = 0 -- NETLINK_ROUTE

function do_syscall(num, domain, stype, proto, arg4, arg5, arg6, arg7, arg8)
    if domain == AF_NETLINK and stype == SOCK_RAW and proto == BAD_PROTO then
        local fd = c_do_syscall(num, domain, stype, FALLBACK_PROTO, arg4 or 0, arg5 or 0, arg6 or 0, arg7 or 0, arg8 or 0)
        if type(fd) == "number" and fd >= 0 then
            if type(c_log) == "function" then
                c_log(string.format("[fix:netlink] socket(AF_NETLINK,SOCK_RAW,%d) -> proto=%d fd=%d", BAD_PROTO, FALLBACK_PROTO, fd))
            end
            return 1, fd
        end
        if type(c_log) == "function" then
            c_log(string.format("[fix:netlink] fallback socket failed ret=%s (pass-through)", tostring(fd)))
        end
    end
    return 0, 0
end
"""

        explain = (
            "API/LLM 返回不满足协议，已启用兜底规则生成。\n"
            "检测到 netlink socket 创建失败：socket(AF_NETLINK=16, SOCK_RAW=3, proto=31) -> -EPROTONOSUPPORT(-93)。\n"
            "兜底规则将 proto=31 映射到 NETLINK_ROUTE(0) 创建真实 fd，让固件继续走后续 netlink 逻辑。\n"
            "风险：不同固件可能期望特定 netlink 协议号语义；映射可能导致功能缺失，但通常优于直接退出。\n"
        )

        return {
            "fix": {
                "syscall/socket.lua": socket_lua,
            },
            "observe": {},
            "explain": explain,
        }

    # 场景 1：/dev/log connect() -> -ENOENT
    if name != "connect":
        return None

    ret = last_err.get("ret")
    if ret != -2:  # -ENOENT
        return None

    args = last_err.get("args")
    if not isinstance(args, list) or len(args) < 3:
        return None

    sockfd = safe_int(args[0], -1)
    addr_ptr = safe_int(args[1], 0)
    addrlen = safe_int(args[2], 0)
    if sockfd < 0 or addr_ptr == 0 or addrlen <= 0:
        return None

    # 从 snapshot.memory 里找到 last_err_arg2 的二进制 dump（优先），否则按地址匹配
    mem = snapshot.get("memory")
    blob_path = ""
    if isinstance(mem, list):
        for it in mem:
            if not isinstance(it, dict):
                continue
            tag = it.get("tag")
            if isinstance(tag, str) and tag.startswith("last_err_arg2_"):
                # 运行目录内路径最可靠：run_dir/memory/<tag>.bin
                cand = os.path.join(run_dir, "memory", f"{tag}.bin")
                if os.path.exists(cand):
                    blob_path = cand
                    break
                blob = it.get("blob")
                if isinstance(blob, dict):
                    p = blob.get("file")
                    if isinstance(p, str) and p:
                        blob_path = p
                        break
        if not blob_path:
            for it in mem:
                if not isinstance(it, dict):
                    continue
                if safe_int(it.get("addr"), -1) != addr_ptr:
                    continue
                blob = it.get("blob")
                if isinstance(blob, dict):
                    p = blob.get("file")
                    if isinstance(p, str) and p:
                        blob_path = p
                        break

    if not blob_path:
        return None

    abs_blob = blob_path if os.path.isabs(blob_path) else os.path.abspath(blob_path)
    try:
        raw = open(abs_blob, "rb").read()
    except Exception:
        return None

    sock_path = decode_unix_sock_path(raw[: max(addrlen, 0)])
    if sock_path != "/dev/log":
        return None

    # 生成规则：避免 /dev/log 缺失导致退出
    # 1) connect(/dev/log) 直接成功，并把 fd 标记为“syslog fd”
    # 2) write/sendto/sendmsg 对该 fd 丢弃但返回成功
    # 3) close 时清理标记，避免 fd 复用误伤
    # 4) exit_group：仅用于本轮重试（不导出 stable_rules）
    connect_lua = """-- sfemu:transient=0
-- 自动修复规则：/dev/log syslog 兼容（connect）
-- 说明：部分固件在 syslog socket(/dev/log) 不存在时会直接 exit_group。
-- 本规则仅在目标为 /dev/log 时命中：让 connect() 返回成功，并标记该 fd 供后续 write/send* 丢弃。

local function log(msg)
    if type(c_log) == "function" then
        c_log(msg)
    end
end

local AF_UNIX = 1

local function read_u16_le(bytes)
    if not bytes or #bytes < 2 then
        return nil
    end
    return string.byte(bytes, 1) + (string.byte(bytes, 2) << 8)
end

local function read_unix_path(sockaddr_addr)
    local family_bytes, rc = c_read_bytes(sockaddr_addr, 2)
    if rc ~= 0 then
        return nil, nil
    end
    local family = read_u16_le(family_bytes)
    if family ~= AF_UNIX then
        return nil, family
    end
    local path, rc2 = c_read_string(sockaddr_addr + 2, 108)
    if rc2 ~= 0 then
        return nil, family
    end
    path = (path or \"\"):match(\"^([^%z]*)\")
    return path, family
end

local function mark_syslog_fd(fd)
    if type(_G._sfemu_syslog_fds) ~= \"table\" then
        _G._sfemu_syslog_fds = {}
    end
    _G._sfemu_syslog_fds[fd] = true
end

local base_do = nil
do
    -- 作为 override 规则使用：未命中 /dev/log 时，继续复用基础规则逻辑
    local script_dir = debug.getinfo(1, \"S\").source:match(\"@?(.*/)\") or \"\"
    local rules_dir = script_dir:gsub(\"syscall_override/?$\", \"\"):gsub(\"syscall/?$\", \"\")
    local base_path = rules_dir .. \"syscall/connect.lua\"
    local base_env = setmetatable({}, { __index = _G })
    local chunk = loadfile(base_path, \"t\", base_env)
    if chunk then
        pcall(chunk)
        if type(base_env.do_syscall) == \"function\" then
            base_do = base_env.do_syscall
        end
    end
end

function do_syscall(num, sockfd, addr, addrlen, arg4, arg5, arg6, arg7, arg8)
    if addr ~= 0 then
        local path = read_unix_path(addr)
        if path == \"/dev/log\" then
            mark_syslog_fd(sockfd)
            log(string.format(\"[fix:/dev/log] connect fd=%d -> /dev/log (force success)\", sockfd or -1))
            return 1, 0
        end
    end
    if type(base_do) == \"function\" then
        return base_do(num, sockfd, addr, addrlen, arg4, arg5, arg6, arg7, arg8)
    end
    return 0, 0
end
"""

    close_lua = """-- sfemu:transient=0
-- 自动修复规则：/dev/log syslog 兼容（close）
-- 说明：清理 syslog fd 标记，避免 fd 复用误伤。

local function unmark(fd)
    local m = rawget(_G, \"_sfemu_syslog_fds\")
    if type(m) ~= \"table\" then
        return
    end
    m[fd] = nil
end

local base_do = nil
do
    local script_dir = debug.getinfo(1, \"S\").source:match(\"@?(.*/)\") or \"\"
    local rules_dir = script_dir:gsub(\"syscall_override/?$\", \"\"):gsub(\"syscall/?$\", \"\")
    local base_path = rules_dir .. \"syscall/close.lua\"
    local base_env = setmetatable({}, { __index = _G })
    local chunk = loadfile(base_path, \"t\", base_env)
    if chunk then
        pcall(chunk)
        if type(base_env.do_syscall) == \"function\" then
            base_do = base_env.do_syscall
        end
    end
end

function do_syscall(num, fd, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    unmark(fd)
    if type(base_do) == \"function\" then
        return base_do(num, fd, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    end
    return 0, 0
end
"""

    write_lua = """-- sfemu:transient=0
-- 自动修复规则：/dev/log syslog 兼容（write）
-- 说明：对已标记的 syslog fd，丢弃写入但返回成功。

local function is_syslog_fd(fd)
    local m = rawget(_G, \"_sfemu_syslog_fds\")
    return type(m) == \"table\" and m[fd] == true
end

local base_do = nil
do
    local script_dir = debug.getinfo(1, \"S\").source:match(\"@?(.*/)\") or \"\"
    local rules_dir = script_dir:gsub(\"syscall_override/?$\", \"\"):gsub(\"syscall/?$\", \"\")
    local base_path = rules_dir .. \"syscall/write.lua\"
    local base_env = setmetatable({}, { __index = _G })
    local chunk = loadfile(base_path, \"t\", base_env)
    if chunk then
        pcall(chunk)
        if type(base_env.do_syscall) == \"function\" then
            base_do = base_env.do_syscall
        end
    end
end

function do_syscall(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    if is_syslog_fd(fd) then
        local n = tonumber(count) or 0
        if n < 0 then
            n = 0
        end
        if type(c_log) == \"function\" then
            c_log(string.format(\"[fix:/dev/log] write fd=%d count=%d (discard)\", fd or -1, n))
        end
        return 1, n
    end
    if type(base_do) == \"function\" then
        return base_do(num, fd, buf, count, arg4, arg5, arg6, arg7, arg8)
    end
    return 0, 0
end
"""

    sendto_lua = """-- sfemu:transient=0
-- 自动修复规则：/dev/log syslog 兼容（sendto）
-- 说明：对已标记的 syslog fd，丢弃发送但返回成功。

local function is_syslog_fd(fd)
    local m = rawget(_G, \"_sfemu_syslog_fds\")
    return type(m) == \"table\" and m[fd] == true
end

function do_syscall(num, fd, buf, len, flags, addr, addrlen, arg7, arg8)
    if is_syslog_fd(fd) then
        local n = tonumber(len) or 0
        if n < 0 then
            n = 0
        end
        if type(c_log) == \"function\" then
            c_log(string.format(\"[fix:/dev/log] sendto fd=%d len=%d (discard)\", fd or -1, n))
        end
        return 1, n
    end
    return 0, 0
end
"""

    sendmsg_lua = """-- sfemu:transient=0
-- 自动修复规则：/dev/log syslog 兼容（sendmsg）
-- 说明：对已标记的 syslog fd，丢弃发送但返回成功。
-- 为了尽量贴近真实行为，会尝试从 msghdr+iovec 计算本次发送的字节数；解析失败则回退为 0。

local function is_syslog_fd(fd)
    local m = rawget(_G, \"_sfemu_syslog_fds\")
    return type(m) == \"table\" and m[fd] == true
end

local function read_u32_le(bytes, off)
    off = off or 1
    if not bytes or #bytes < off + 3 then
        return nil
    end
    local b1 = string.byte(bytes, off)
    local b2 = string.byte(bytes, off + 1)
    local b3 = string.byte(bytes, off + 2)
    local b4 = string.byte(bytes, off + 3)
    return b1 + (b2 << 8) + (b3 << 16) + (b4 << 24)
end

local function calc_sendmsg_len(msghdr_ptr)
    if not msghdr_ptr or msghdr_ptr == 0 then
        return 0
    end
    -- 针对 32-bit ARM 的 struct msghdr 布局（指针/size_t 均 4B）
    local hdr, rc = c_read_bytes(msghdr_ptr, 28)
    if rc ~= 0 or not hdr or #hdr < 28 then
        return 0
    end
    local iov_ptr = read_u32_le(hdr, 9)
    local iov_len = read_u32_le(hdr, 13)
    if not iov_ptr or not iov_len then
        return 0
    end
    if iov_ptr == 0 or iov_len <= 0 or iov_len > 64 then
        return 0
    end
    local total = 0
    for i = 0, iov_len - 1 do
        local iov, rc2 = c_read_bytes(iov_ptr + i * 8, 8)
        if rc2 ~= 0 or not iov or #iov < 8 then
            break
        end
        local one = read_u32_le(iov, 5) or 0
        if one < 0 then
            one = 0
        end
        total = total + one
    end
    if total < 0 then
        total = 0
    end
    return total
end

function do_syscall(num, fd, msg, flags, arg4, arg5, arg6, arg7, arg8)
    if is_syslog_fd(fd) then
        local n = calc_sendmsg_len(msg)
        if type(c_log) == \"function\" then
            c_log(string.format(\"[fix:/dev/log] sendmsg fd=%d len=%d (discard)\", fd or -1, n))
        end
        return 1, n
    end
    return 0, 0
end
"""

    exit_group_lua = """-- sfemu:transient=1
-- 自动修复规则：exit_group（仅用于 AI 本轮重试）
-- 说明：
-- - 本规则不属于“根因修复”，仅用于在 AI 应用修复规则后，阻止本次立即退出，让进程继续运行以验证修复是否生效。
-- - 仅在 AI 验证窗口 active 时拦截一次；验证窗口结束后不再拦截。

local function should_suppress_once()
    local st = rawget(_G, \"_sfemu_ai_state\")
    if type(st) ~= \"table\" then
        return false
    end
    local v = st.verify
    if type(v) ~= \"table\" or v.active ~= true then
        return false
    end
    if v._exit_group_suppressed == true then
        return false
    end
    v._exit_group_suppressed = true
    return true
end

function do_syscall(num, status, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
    if should_suppress_once() then
        if type(c_log) == \"function\" then
            c_log(string.format(\"[fix:/dev/log] suppress exit_group once (status=%s) for AI retry\", tostring(status)))
        end
        return 1, 0
    end
    return 0, 0
end
"""

    explain = (
        "API/LLM 返回不满足协议，已启用兜底规则生成。\n"
        "检测到典型问题链路：connect(AF_UNIX, '/dev/log') -> -ENOENT 后触发 exit_group。\n"
        "本次兜底规则会：\n"
        "- 对 /dev/log 的 connect 强制返回成功，并标记 fd；\n"
        "- 对该 fd 的 write/sendto/sendmsg 丢弃但返回成功；\n"
        "- close 时清理标记；\n"
        "- exit_group 在 AI 验证窗口 active 时仅拦截一次（用于本轮重试；该规则标记为 transient，不会导出 stable_rules）。\n"
        "风险：拦截 exit_group 可能导致程序在理论上进入未定义路径，但仅用于验证修复、且只拦截一次。\n"
    )

    return {
        "fix": {
            "syscall/connect.lua": connect_lua,
            "syscall/close.lua": close_lua,
            "syscall/write.lua": write_lua,
            "syscall/sendto.lua": sendto_lua,
            "syscall/sendmsg.lua": sendmsg_lua,
            "syscall/exit_group.lua": exit_group_lua,
        },
        "observe": {},
        "explain": explain,
    }


def safe_relpath(rel: str) -> str:
    rel = (rel or "").replace("\\", "/").lstrip("/")
    rel = re.sub(r"/+", "/", rel)
    # 防止目录穿越
    rel = rel.replace("../", "").replace("..\\", "")
    return rel


def write_rule_files(patch_dir: str, obj: Dict[str, Any]) -> None:
    def write_kind(kind: str) -> int:
        m = obj.get(kind)
        if not isinstance(m, dict):
            return 0
        n = 0
        for rel, content in m.items():
            if not isinstance(rel, str) or not isinstance(content, str):
                continue
            rel = safe_relpath(rel)
            # 允许模型输出 "syscall/xxx.lua"；落到 rules_patch/<kind>/syscall/xxx.lua
            if rel.startswith("syscall/"):
                out_path = os.path.join(patch_dir, kind, rel)
            elif rel.startswith(f"{kind}/"):
                out_path = os.path.join(patch_dir, rel)
            else:
                out_path = os.path.join(patch_dir, kind, rel)

            out_dir = os.path.dirname(out_path)
            os.makedirs(out_dir, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
                if not content.endswith("\n"):
                    f.write("\n")
            n += 1
        return n

    n_fix = write_kind("fix")
    n_obs = write_kind("observe")

    explain = obj.get("explain")
    if isinstance(explain, str) and explain.strip():
        with open(os.path.join(patch_dir, "ai_explain.md"), "w", encoding="utf-8") as f:
            f.write(explain.strip() + "\n")

    meta = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "fix_files": n_fix,
        "observe_files": n_obs,
    }
    with open(os.path.join(patch_dir, "ai_result_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
        f.write("\n")


def write_actions_files(patch_dir: str, runner: ActionRunner) -> None:
    try:
        with open(os.path.join(patch_dir, "ai_actions.json"), "w", encoding="utf-8") as f:
            json.dump(
                {
                    "mutations_applied": runner.mutations_applied,
                    "actions": runner.actions,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
            f.write("\n")
    except Exception:
        pass

    # 给 Lua 侧一个“无需 JSON 解析”的最小信号：本轮是否执行了写入类动作
    try:
        with open(os.path.join(patch_dir, "ai_actions_applied.txt"), "w", encoding="utf-8") as f:
            f.write(str(int(runner.mutations_applied)) + "\n")
    except Exception:
        pass


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        eprint("usage: ai_mcp_openai.py <snapshot.json> <rules_patch_dir> <env_path>")
        return 2

    snapshot_path = argv[1]
    patch_dir = argv[2]
    env_path = argv[3]

    env = load_env(env_path)

    # patch_dir 是 run_dir/rules_patch
    run_dir = os.path.dirname(os.path.abspath(patch_dir))
    os.makedirs(os.path.join(patch_dir, "fix", "syscall"), exist_ok=True)
    os.makedirs(os.path.join(patch_dir, "observe", "syscall"), exist_ok=True)

    try:
        with open(snapshot_path, "r", encoding="utf-8") as f:
            snapshot = json.load(f)
    except UnicodeDecodeError as ex:
        # 兼容旧版本快照：可能包含非 UTF-8 字节（例如从 guest 内存读到的“伪字符串”）
        # 这里用 replace 兜底，避免直接退出；结构字段仍能被 JSON 正常解析。
        try:
            with open(snapshot_path, "rb") as f:
                raw = f.read()
            snapshot = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception as ex2:
            eprint(f"[ai_mcp_openai] 读取 snapshot 失败: {ex} / fallback={ex2}")
            return 3
    except Exception as ex:
        eprint(f"[ai_mcp_openai] 读取 snapshot 失败: {ex}")
        return 3

    system_prompt, user_prompt = build_prompt(snapshot, run_dir, env)

    # actions/tool_calls：默认关闭，避免误写宿主机；需要时在 env 中显式开启。
    safe_root = env.get("SFEMU_AI_MCP_SAFE_ROOT") or env.get("SFEMU_AI_SAFE_ROOT") or ""
    safe_root = safe_root.strip() or (detect_safe_root(run_dir) or "")

    tools_enable = str_bool(env.get("SFEMU_AI_MCP_TOOLS_ENABLE") or env.get("SFEMU_AI_MCP_TOOLS"), False)
    actions_enable = str_bool(env.get("SFEMU_AI_MCP_ACTIONS_ENABLE") or env.get("SFEMU_AI_MCP_ACTIONS"), False)
    shell_enable = str_bool(env.get("SFEMU_AI_MCP_SHELL_ENABLE"), False)
    net_enable = str_bool(env.get("SFEMU_AI_MCP_NET_ENABLE") or env.get("SFEMU_AI_MCP_NET"), False)
    ip_bin = env.get("SFEMU_AI_MCP_IP_BIN") or ""
    assume_container = str_bool(env.get("SFEMU_AI_MCP_ASSUME_CONTAINER") or env.get("SFEMU_AI_MCP_NET_ASSUME_CONTAINER"), False)

    runner = ActionRunner(
        safe_root if safe_root else None,
        allow_write=actions_enable,
        allow_shell=shell_enable,
        allow_net=net_enable,
        ip_bin=ip_bin,
        assume_container=assume_container,
    )
    tools_spec = build_tools_spec(env, allow_write=actions_enable, allow_shell=shell_enable, allow_net=net_enable) if tools_enable else None

    # ----------------------------
    # 轻量自愈（不依赖外部 API）
    # ----------------------------
    # sleep_loop 常见根因是“等待网络/桥接接口/LAN IP”，若依赖 LLM 生成规则不仅慢且不稳定。
    # 这里提供一个默认开启的、自包含的 playbook：
    # - 尝试补齐 br0/eth0 的 LAN IP（默认 192.168.1.1/24）
    # - 将 select/pselect6 的超长 timeout 缩短到 200ms（只改内存，不拦截返回值），让状态机更快重新评估条件
    #
    # 可通过 env 关闭：SFEMU_AI_MCP_AUTOFIX_SLEEP_LOOP=0
    try:
        autofix_on = str_bool(env.get("SFEMU_AI_MCP_AUTOFIX_SLEEP_LOOP"), True)
    except Exception:
        autofix_on = True

    if autofix_on and (snapshot.get("reason") == "sleep_loop"):
        lan_cidr = (env.get("SFEMU_AI_LAN_CIDR") or "192.168.1.1/24").strip()
        lan_if = (env.get("SFEMU_AI_LAN_IFACE") or "br0").strip() or "br0"

        # 1) 网络补齐（可选）
        if net_enable:
            runner.net_if_list()
            # 先试 bridge，再退化 dummy；最后再尝试在 eth0 上加地址（避免 br0 创建失败导致完全无效）
            r1 = runner.net_ensure_addr(lan_if, lan_cidr, kind="bridge", up=True)
            if not (isinstance(r1, dict) and r1.get("ok") is True):
                runner.net_ensure_addr(lan_if, lan_cidr, kind="dummy", up=True)
            runner.net_ensure_addr("eth0", lan_cidr, kind="dummy", up=True)

        # 2) 生成“缩短 sleep”的通用规则（尽量不拦截，只改 timeout 结构体）
        # 说明：该规则用于加速固件状态机推进，避免每轮 sleep 60s 导致 Docker wait 超时。
        fix_select = r"""
-- select.lua (autofix) - 将 nfds=0 的长/无 timeout 缩短为 200ms，避免固件在 sleep_loop 中卡住

local SYSCALL_SELECT = 142
local SYSCALL_MMAP2 = 192

local PROT_READ = 0x1
local PROT_WRITE = 0x2
local MAP_PRIVATE = 0x2
local MAP_ANONYMOUS = 0x20

local g_scratch = 0

local function u32_le(x)
  x = tonumber(x) or 0
  x = x & 0xffffffff
  return string.char(x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff)
end

local function get_scratch()
  if g_scratch ~= 0 then
    return g_scratch
  end
  if type(c_do_syscall) ~= "function" or type(c_write_bytes) ~= "function" then
    return 0
  end
  local addr = 0
  local length = 4096
  local prot = PROT_READ | PROT_WRITE
  local flags = MAP_PRIVATE | MAP_ANONYMOUS
  local fd = -1
  local off = 0
  local ret = c_do_syscall(SYSCALL_MMAP2, addr, length, prot, flags, fd, off, 0, 0)
  if type(ret) == "number" and ret > 0 then
    g_scratch = ret
  end
  return g_scratch
end

local function patch_timeval(ptr, tv_sec, tv_usec)
  ptr = tonumber(ptr) or 0
  if ptr == 0 or type(c_write_bytes) ~= "function" then
    return false
  end
  local data = u32_le(tv_sec) .. u32_le(tv_usec)
  local _, rc = c_write_bytes(ptr, data)
  return rc == 0
end

function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
  if tonumber(num) ~= SYSCALL_SELECT then
    return 0, 0
  end

  local nfds = tonumber(arg1) or -1
  local readfds = arg2
  local writefds = arg3
  local exceptfds = arg4
  local timeout = tonumber(arg5) or 0

  if nfds ~= 0 then
    return 0, 0
  end

  -- 1) 有 timeout：直接把 timeval 改小，再放行真实 syscall
  if timeout ~= 0 then
    patch_timeval(timeout, 0, 200000)
    return 0, 0
  end

  -- 2) timeout==NULL（无限阻塞）：用 scratch timeval 执行一次“带 200ms timeout 的真实 select”
  local tv = get_scratch()
  if tv ~= 0 then
    patch_timeval(tv, 0, 200000)
    local r = c_do_syscall(SYSCALL_SELECT, nfds, readfds, writefds, exceptfds, tv, 0, 0, 0)
    return 1, r
  end

  -- 兜底：直接返回 0（可能导致 busy loop，但至少不会永久卡死）
  return 1, 0
end
""".lstrip("\n")

        fix_pselect6 = r"""
-- pselect6.lua (autofix) - 将 nfds=0 的长/无 timeout 缩短为 200ms，避免固件在 sleep_loop 中卡住

local SYSCALL_PSELECT6 = 335
local SYSCALL_MMAP2 = 192

local PROT_READ = 0x1
local PROT_WRITE = 0x2
local MAP_PRIVATE = 0x2
local MAP_ANONYMOUS = 0x20

local g_scratch = 0

local function u32_le(x)
  x = tonumber(x) or 0
  x = x & 0xffffffff
  return string.char(x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff)
end

local function get_scratch()
  if g_scratch ~= 0 then
    return g_scratch
  end
  if type(c_do_syscall) ~= "function" or type(c_write_bytes) ~= "function" then
    return 0
  end
  local addr = 0
  local length = 4096
  local prot = PROT_READ | PROT_WRITE
  local flags = MAP_PRIVATE | MAP_ANONYMOUS
  local fd = -1
  local off = 0
  local ret = c_do_syscall(SYSCALL_MMAP2, addr, length, prot, flags, fd, off, 0, 0)
  if type(ret) == "number" and ret > 0 then
    g_scratch = ret
  end
  return g_scratch
end

local function patch_timespec(ptr, tv_sec, tv_nsec)
  ptr = tonumber(ptr) or 0
  if ptr == 0 or type(c_write_bytes) ~= "function" then
    return false
  end
  local data = u32_le(tv_sec) .. u32_le(tv_nsec)
  local _, rc = c_write_bytes(ptr, data)
  return rc == 0
end

function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
  if tonumber(num) ~= SYSCALL_PSELECT6 then
    return 0, 0
  end

  local nfds = tonumber(arg1) or -1
  local readfds = arg2
  local writefds = arg3
  local exceptfds = arg4
  local timeout = tonumber(arg5) or 0
  local sigmask = arg6
  local extra7 = arg7
  local extra8 = arg8

  if nfds ~= 0 then
    return 0, 0
  end

  if timeout ~= 0 then
    patch_timespec(timeout, 0, 200000000)
    return 0, 0
  end

  local ts = get_scratch()
  if ts ~= 0 then
    patch_timespec(ts, 0, 200000000)
    local r = c_do_syscall(SYSCALL_PSELECT6, nfds, readfds, writefds, exceptfds, ts, sigmask, extra7, extra8)
    return 1, r
  end

  return 1, 0
end
""".lstrip("\n")

        obj = {
            "fix": {
                "syscall/select.lua": fix_select,
                "syscall/pselect6.lua": fix_pselect6,
            },
            "observe": {},
            "explain": (
                "sleep_loop 自愈：\n"
                "- (可选) 补齐 LAN IP：{iface} -> {cidr}（优先 bridge，失败退化 dummy；同时尝试 eth0）。\n"
                "- 缩短 select/pselect6(nfds=0) 的 timeout 到 200ms：\n"
                "  - 若 timeout 非空：仅改 timeout 结构体后放行；\n"
                "  - 若 timeout==NULL：用 scratch timeval/timespec 执行一次“带 200ms timeout 的真实 syscall”（需要拦截一次以返回结果）。\n"
                "\n"
                "风险：可能让固件轮询频率升高；但相比 60s 级 sleep 更利于在批量实验窗口内推进状态机。\n"
                "回滚：删除 syscall_override/select.lua 与 syscall_override/pselect6.lua（或关闭 SFEMU_AI_MCP_AUTOFIX_SLEEP_LOOP）。\n"
            ).format(iface=lan_if, cidr=lan_cidr),
        }

        try:
            write_rule_files(patch_dir, obj)
            write_actions_files(patch_dir, runner)
        except Exception as ex:
            eprint(f"[ai_mcp_openai] autofix_sleep_loop 写入失败: {ex}")
            return 6
        return 0

    try:
        content = run_openai_agent(env, system_prompt, user_prompt, runner, tools_spec)
    except urllib.error.HTTPError as ex:
        body = ex.read().decode("utf-8", errors="replace") if hasattr(ex, "read") else ""
        eprint(f"[ai_mcp_openai] HTTPError: {ex} body={body[:2000]}")
        return 4
    except Exception as ex:
        eprint(f"[ai_mcp_openai] 调用 API 失败: {ex}")
        # API 不可用时也尝试兜底（离线可用）
        fallback = build_fallback_rules(snapshot, run_dir)
        if not fallback:
            return 4
        try:
            write_rule_files(patch_dir, fallback)
            write_actions_files(patch_dir, runner)
        except Exception as ex2:
            eprint(f"[ai_mcp_openai] 写规则失败: {ex2}")
            return 6
        return 0

    # 记录原始返回，便于追溯（注意：不包含 api_key）
    try:
        with open(os.path.join(patch_dir, "ai_raw_response.txt"), "w", encoding="utf-8") as f:
            f.write(content)
            if not content.endswith("\n"):
                f.write("\n")
    except Exception:
        pass

    try:
        obj = extract_first_json(content)
    except Exception as ex:
        # 常见：模型忽略“只输出 JSON”的要求，返回了分析文本。
        # 为避免整条链路中断，这里提供“快照启发式兜底”，生成一组最小可用规则。
        eprint(f"[ai_mcp_openai] 解析 LLM JSON 失败: {ex}")
        fallback = build_fallback_rules(snapshot, run_dir)
        if not fallback:
            # 无法兜底：把原始回复写入 explain，仍然产出 meta，便于人工排查
            fallback = {
                "fix": {},
                "observe": {},
                "explain": (
                    "LLM 未按协议输出 JSON，且当前快照不满足已实现的兜底规则模式。\n\n"
                    "原始回复如下（可能包含建议）：\n\n"
                    + (content or "").strip()
                ),
            }
        else:
            # 补充：把原始回复一起落盘，便于追溯
            fallback["explain"] = (fallback.get("explain") or "") + "\n\n---\n\n原始 LLM 回复（非 JSON）：\n\n" + (content or "").strip()
        obj = fallback

    try:
        write_rule_files(patch_dir, obj)
        # 允许模型在最终 JSON 中额外返回 actions（当网关不支持 tool_calls 时尤其有用）
        acts = obj.get("actions")
        if actions_enable and isinstance(acts, list):
            for it in acts:
                if not isinstance(it, dict):
                    continue
                tool = it.get("tool") or it.get("name")
                args = it.get("args") if isinstance(it.get("args"), dict) else {}
                if tool:
                    runner.run_action(str(tool), args)
        write_actions_files(patch_dir, runner)
    except Exception as ex:
        eprint(f"[ai_mcp_openai] 写规则失败: {ex}")
        return 6

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
