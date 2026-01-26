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


def build_prompt(snapshot: Dict[str, Any], run_dir: str) -> Tuple[str, str]:
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

    req = urllib.request.Request(
        base_url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )

    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read()
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

    # 允许模型偶尔带一些前后缀，这里尽量截取第一个 JSON 对象
    start = t.find("{")
    end = t.rfind("}")
    if start >= 0 and end > start:
        t = t[start : end + 1]

    return json.loads(t)


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

    system_prompt, user_prompt = build_prompt(snapshot, run_dir)

    try:
        content = call_openai_chat(env, system_prompt, user_prompt)
    except urllib.error.HTTPError as ex:
        body = ex.read().decode("utf-8", errors="replace") if hasattr(ex, "read") else ""
        eprint(f"[ai_mcp_openai] HTTPError: {ex} body={body[:2000]}")
        return 4
    except Exception as ex:
        eprint(f"[ai_mcp_openai] 调用 API 失败: {ex}")
        return 4

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
        eprint(f"[ai_mcp_openai] 解析 LLM JSON 失败: {ex}")
        return 5

    try:
        write_rule_files(patch_dir, obj)
    except Exception as ex:
        eprint(f"[ai_mcp_openai] 写规则失败: {ex}")
        return 6

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
