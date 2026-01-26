# config 目录说明

本目录用于放置“规则运行时配置”，尤其是 AI 干预相关的配置（例如 OpenAI key、baseurl 等）。

## env 文件

默认使用 `config/env`：

- `rules_examples/entry.lua` 在加载时会读取该文件，并把 `KEY=VALUE` 写入 Lua 全局变量（`_G`）。
- `rules_examples/base/ai.lua` 会从 `_G` 读取 `SFEMU_AI_*` 配置。

安全提示：

- `config/env` 通常包含密钥/令牌，仓库已通过 `.gitignore` 忽略该文件，避免误提交。

## 外部 AI 工具接口（SFEMU_AI_CMD）

当触发“退出/死循环”干预时，若配置了 `SFEMU_AI_CMD`，框架会执行：

```
$SFEMU_AI_CMD <snapshot.json> <rules_patch_dir> <env_path>
```

其中：

- `snapshot.json`：上下文快照索引（寄存器/调用栈/伪代码索引/内存证据/近期 syscall 等）。
- `rules_patch_dir`：本轮干预输出目录（外部工具在此写入规则）。
- `env_path`：当前 env 文件路径（外部工具可自行解析以获取 OPENAI_* 等配置）。

推荐输出结构（外部工具生成）：

- `rules_patch/fix/syscall/<name>.lua`：修复型规则（默认会被自动应用，并参与 stable_rules 导出）
- `rules_patch/observe/syscall/<name>.lua`：观测型规则（默认不自动应用，仅用于定位）

## 内置“类 MCP”（无需自写脚本）

如果你希望在检测到 `exit/exit_group` 或“死循环”时，框架自动调用 API 生成规则并继续运行：

- 在 `config/env` 中设置：`SFEMU_AI_MCP_ENABLE=1`
- 填好：`OPENAI_API_KEY`、`OPENAI_BASE_URL`、`OPENAI_MODEL`
- 若希望生成的修复规则能立刻生效（覆盖已有 `syscall/<name>.lua`），设置：`SFEMU_AI_OVERWRITE_RULES=1`（会自动备份到 `ai_runs/<run_id>/backup_syscall/`）

此时若未显式设置 `SFEMU_AI_CMD`，框架会默认执行：

`python3 rules_examples/tools/ai_mcp_openai.py <snapshot.json> <rules_patch_dir> <env_path>`
