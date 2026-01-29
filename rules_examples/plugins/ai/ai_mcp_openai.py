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
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, Any, Tuple, Optional


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
        "你的任务是：生成最小、可回滚、尽量精确命中的 Lua syscall 规则，用于修复仿真失败并让固件继续运行。\n"
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
        "  \"explain\": \"简要说明为什么这么改，以及风险/回滚点\"\n"
        "}\n"
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


def call_openai_chat(env: Dict[str, str], system_prompt: str, user_prompt: str) -> str:
    api_key = env.get("OPENAI_API_KEY") or env.get("OPENAI_KEY") or ""
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY 未设置")

    model = env.get("OPENAI_MODEL") or "gpt-4o-mini"
    base_url = normalize_chat_completions_url(env.get("OPENAI_BASE_URL") or env.get("OPENAI_BASEURL") or "")

    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }

    def do_request(p: Dict[str, Any]) -> bytes:
        req = urllib.request.Request(
            base_url,
            data=json.dumps(p).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.read()

    # 尽量启用 JSON mode（OpenAI/Gateway 常支持 response_format=json_object），强制模型输出 JSON，避免解析失败。
    # 兼容性：若网关不支持该字段，回退到普通模式。
    json_mode = env.get("OPENAI_JSON_MODE") or env.get("SFEMU_AI_JSON_MODE")
    json_mode_on = json_mode is None or str(json_mode).strip().lower() in ("1", "true", "yes", "y", "on")
    data = b""
    if json_mode_on:
        payload_json = dict(payload)
        payload_json["response_format"] = {"type": "json_object"}
        try:
            data = do_request(payload_json)
        except urllib.error.HTTPError as ex:
            body = ex.read().decode("utf-8", errors="replace") if hasattr(ex, "read") else ""
            # 常见不支持表现：unknown field/extra inputs/response_format not permitted 等
            if ex.code in (400, 404) and ("response_format" in body or "unknown" in body.lower() or "extra" in body.lower()):
                data = do_request(payload)
            else:
                raise
    else:
        data = do_request(payload)

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

    try:
        content = call_openai_chat(env, system_prompt, user_prompt)
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
    except Exception as ex:
        eprint(f"[ai_mcp_openai] 写规则失败: {ex}")
        return 6

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
