# SFEmu Lua Rules（规则目录）使用说明 & API

本目录是 **QEMU 用户态仿真（linux-user）** 的 Lua 规则入口：通过 `entry.lua/finish.lua` 在 syscall 前后介入，实现：

- 观测：记录 syscall、回溯、参数与返回值
- 兼容：用 Lua 对缺失文件/设备/内核差异做最小补齐
- 自动化修复：在异常退出/死循环/长时间无 syscall 时触发 AI 生成规则并自动应用

---

## 1. 快速开始

### 1.1 运行（示例）

规则目录通过 QEMU 参数 `-rules <dir>` 指定。典型启动形态：

```bash
./qemu-arm -L . \
  -rules ./rules_examples/ \
  -rules-ctx-keep 256 \
  -rules-idle-ms 1000 \
  -shadowstack log=off,summary=on,unwind_limit=100,max_stack=100 \
  -sfanalysis ./out_httpd \
  /usr/sbin/httpd
```

### 1.2 验证（curl 地址）

如果固件的 httpd 监听在本机回环（常见），在“运行 httpd 的同一环境”里验证：

```bash
curl -v http://127.0.0.1/
curl -v http://127.0.0.1/index.asp
```

---

## 2. 目录结构（重构后）

```
rules_examples/
  entry.lua                  # syscall 入口：分发、缓存、死循环检测、触发 AI
  finish.lua                 # syscall 结束：统一记录 ret/intercepted 等

  plugins/                   # 插件式工具
    fakefile/                # fakefile：缺失文件/设备/socket 的“伪资源”补齐框架
    ai/ai_mcp_openai.py      # 内置 AI 工具：读 snapshot -> 调 OpenAI 兼容 API -> 生成规则 patch

  syscall_override_user/     # 固件/型号相关的自定义规则（优先级最高）
  syscall_override/          # AI/临时修复规则（运行时生成；优先级高于 syscall/）
  syscall/                   # 默认 syscall 规则

  base/                      # 通用基础库（可复用 API）
  config/                    # 配置：config/env 会被 entry.lua 自动加载
    env.example              # 可提交模板（真实密钥写到本地 config/env）
    ssl/                     # 内置证书/密钥模板（供 bootstrap_fs 补齐 /etc/*.pem）

  cache/                     # 运行时缓存/落盘输出（ctx、死循环报告、ai_runs、stable_rules）
  log/                       # 日志（可选）
```

---

## 3. syscall 规则 API

### 3.1 规则文件命名

- 默认规则放在：`syscall/<syscall_name>.lua`
- 覆盖规则放在：`syscall_override_user/<syscall_name>.lua` 或 `syscall_override/<syscall_name>.lua`

### 3.2 `do_syscall` 接口

每个规则文件必须定义：

```lua
function do_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8)
  -- return action, ret
end
```

返回值约定：

- `action = 0`：不拦截，继续执行真实 syscall
- `action = 1`：拦截，直接返回 `ret`
  - `ret >= 0`：成功返回值
  - `ret < 0`：错误码（负 errno），例如 `-2` 表示 `-ENOENT`

### 3.3 override 优先级

`entry.lua` 内置的默认优先级：

1) `syscall_override_user/<name>.lua`（固件自定义/人工快速迭代）  
2) `syscall_override/<name>.lua`（AI/临时修复）  
3) `syscall/<name>.lua`（基础规则）

可通过 `SFEMU_RULES_OVERRIDE_DIR` 覆盖（用 `:` 分隔多个目录）。

---

## 4. 可用的 C 辅助函数（规则侧）

下面列出规则中已经使用/依赖的函数（以实际代码为准）：

- `c_log(msg)`：输出日志到 QEMU 侧
- `c_do_syscall(num, ...)`：执行真实 syscall（避免 Lua 拦截递归）
- `c_read_bytes(addr, n)` / `c_write_bytes(addr, data)`：读写 guest 内存字节（用于解析结构体/伪造回复）
- `c_read_string(addr, max_len)`：读 guest C 字符串
- `c_read_guest_bytes(addr, n)`：读 guest 字节（历史接口，部分规则仍会用）
- `c_get_timestamp()`：返回 `(sec, nsec)`
- `c_get_shadowstack()`：返回回溯地址表（需启用 `-shadowstack`）
- `c_resolve_addr(addr, max_bytes)` / `c_resolve_host_addr(addr, max_bytes)`：地址解析（需启用 `-sfanalysis`）
- `c_list_regs()` / `c_get_reg(name)`：寄存器访问（AI 快照采集用）
- `c_async_probe_http(host, timeout_ms)`：异步探测目标服务（死循环前进性用）
- `c_watchdog_suspend(on)`：暂停/恢复 watchdog（AI 干预期间避免误判）
- `c_wait_user_continue(prompt)`：暂停等待人工确认继续（未开启自动继续时用）
- `c_mkdir_p(path, mode)`：创建目录（`bootstrap_fs`/`entry.lua` 写 cache 用）
- `c_open_host(path, flags[, mode])`：宿主侧打开“安全白名单”设备文件（用于把 `/dev/zero` 映射成 `/dev/nvram` 等场景）

---

## 5. AI 干预（自动补全规则）

### 5.1 触发条件

当 `SFEMU_AI_ENABLE=1`（或 `auto_ai=1`）时，`entry.lua` 在以下场景会触发 `base/ai.lua`：

- `exit/exit_group`（异常退出）
- `deadloop`（syscall 重复序列检测到死循环）
- `idle_deadloop`（长时间无 syscall，由 idle watchdog 触发）

补充：

- `auto_ai=1`：无人值守模式（不再提示“输入 YES 继续运行”，自动触发 AI 干预并自动继续）
- `exit/exit_group` 场景下，如果 AI 已应用“修复型规则”且允许自动继续，为了完成“重试验证”，会触发 QEMU 自身 `re-exec` 重新运行目标（可用 `SFEMU_AI_REEXEC_ON_EXIT_FIX=0` 关闭；`SFEMU_REEXEC_MAX` 限制最大重启次数）。
- 为了避免“等到 exit 才介入导致来不及修复”，默认还支持在关键 syscall 返回错误时触发 AI 干预，并在该 syscall 点尝试重试（例如 `open/openat/access/ioctl` 返回 `-ENOENT/-ENODEV/-ENOTTY` 等）：`SFEMU_AI_REPAIR_ON_ERROR=1`（可通过 `SFEMU_AI_REPAIR_SYSCALLS` / `SFEMU_AI_REPAIR_ERRNOS` 收敛范围）。

### 5.2 外部工具接口（`SFEMU_AI_CMD`）

当触发 AI 时，框架会执行：

```bash
$SFEMU_AI_CMD <snapshot.json> <rules_patch_dir> <env_path>
```

外部工具需要输出：

- 修复型规则：`<rules_patch_dir>/fix/syscall/<name>.lua`
- 观测型规则：`<rules_patch_dir>/observe/syscall/<name>.lua`

随后 `base/ai.lua` 会把修复规则默认落到 `syscall_override/`（不覆盖基础 `syscall/`），并进入验证窗口，稳定后导出到 `cache/stable_rules/<run_id>/`。

### 5.3 内置 AI 工具（OpenAI 兼容）

当满足以下条件时，无需手写脚本：

- `SFEMU_AI_MCP_ENABLE=1`
- 未显式设置 `SFEMU_AI_CMD`

框架会自动调用：`plugins/ai/ai_mcp_openai.py`  
它会读取 `config/env`（或 `SFEMU_AI_ENV` 指定的 env 文件）中的 `OPENAI_*` 参数。

建议流程：

1) `cp config/env.example config/env`
2) 填写 `OPENAI_API_KEY / OPENAI_BASE_URL / OPENAI_MODEL`
3) 设置 `SFEMU_AI_ENABLE=1`、`SFEMU_AI_MCP_ENABLE=1`、`SFEMU_AI_AUTO_CONTINUE=1`

---

## 6. 固件相关的关键规则（示例）

- WLCSM/NVRAM（避免 `nvram_get()` 返回 NULL）：`syscall_override_user/sendmsg.lua` + `syscall_override_user/recvmsg.lua`
- 私有 netlink proto=31 前进性兜底：`syscall_override_user/socket.lua`（配合 `SFEMU_NETLINK_VIRTUAL_ACK`）
- SSL/目录补齐（避免 httpd 因证书/目录缺失退出）：`base/bootstrap_fs.lua`（使用 `config/ssl/` 里的模板）
