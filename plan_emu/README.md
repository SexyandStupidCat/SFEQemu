# plan_emu：60 个固件批量仿真记录

本目录用于保存“数据集 60 个目标固件”的批量仿真过程记录与阶段性总结（每 10 个固件总结一次）。

## 目标清单

- 数据集清单：`/media/user/ddisk/Work/FirmAE/firmwares/dataset/targets_60_multibrand_websvc.txt`
  - 格式：`<Web 服务程序绝对路径> <rootfs 绝对路径>`
  - 覆盖多个品牌目录（asus/dlink/netgear/tplink/…），并包含常见 Web 服务实现（httpd/uhttpd/lighttpd/boa/goahead/mini_httpd/webs）。

## 执行方式（脚本）

使用仓库脚本：`lab/run_batch_001.sh`

本轮批量实验为了加速，默认采用“仅动态仿真”的模式（跳过 SDGen/SFAnalysis）：

```bash
EMU_ONLY=1 DOCKER_WAIT_SECS=90 \
  ./lab/run_batch_001.sh /media/user/ddisk/Work/FirmAE/firmwares/dataset/targets_60_multibrand_websvc.txt
```

说明：
- 成功标准：容器内 `curl` 对目标服务任意 host/port 有回包（不要求 200；404 也算“有回包”）。
- 每个固件的原始产物写入固件自身目录：`<rootfs>/sfemu_lab/`（`result.status` / `success.url` / 各类日志）。

## 本目录输出

- `summary_01_10.md` / `summary_11_20.md` …：每 10 个固件的阶段性总结（成功/失败、原因、规则特征、通性问题与默认规则补充）。
- `final_summary.md`：60 个固件总览与最终结论（完成后生成）。

