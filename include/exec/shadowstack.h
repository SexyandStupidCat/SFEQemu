/*
 * shadowstack（qemu-user 内置功能）
 *
 * 目标：在静态编译的 qemu-*-user 中启用影子调用栈跟踪。
 * 实现：由 TCG 翻译阶段插桩生成 helper 调用，运行期维护每 CPU 的 shadow call stack。
 */

#ifndef EXEC_SHADOWSTACK_H
#define EXEC_SHADOWSTACK_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum ShadowStackArch {
    SHADOWSTACK_ARCH_UNKNOWN = 0,
    SHADOWSTACK_ARCH_AARCH64,
    SHADOWSTACK_ARCH_X86_64,
    SHADOWSTACK_ARCH_ARM,
    SHADOWSTACK_ARCH_MIPS,
} ShadowStackArch;

/*
 * 初始化/配置（可重复调用，后一次覆盖前一次）。
 *
 * optstr 语法（逗号分隔）：
 * - on/off：开启/关闭（默认 on）
 * - log=on|off：逐事件输出（默认 off）
 * - summary=on|off：退出时汇总（默认 on）
 * - unwind_limit=N：回溯匹配 ret_addr 的最大弹栈深度（默认 10，0 表示不限制）
 * - max_stack=N：shadow stack 最大深度（默认 0 表示不限制）
 *
 * 返回 0 表示成功，<0 表示失败（已输出错误信息）。
 */
int shadowstack_init_from_opts(const char *target_name, const char *optstr);

bool shadowstack_is_enabled(void);
ShadowStackArch shadowstack_arch(void);
bool shadowstack_is_big_endian(void);

/*
 * TCG 注入的运行期 helper（由 accel/tcg/translator.c 生成调用）。
 * 注意：这些函数会在热点路径中被频繁调用，必须保持轻量。
 */
void shadowstack_helper_tb_exec(uint32_t cpu_index, uint64_t pc);
void shadowstack_helper_call_exec(uint32_t cpu_index, uint64_t callsite,
                                  uint64_t ret_addr);

/*
 * 导出 shadowstack 的“返回地址（ret_addr）”列表（从栈底到栈顶）。
 * 返回值为新分配的数组；用 g_free() 释放。未启用或为空则返回 NULL 且 *out_len=0。
 */
uint64_t *shadowstack_copy_ret_addrs(uint32_t cpu_index, size_t *out_len);

#endif /* EXEC_SHADOWSTACK_H */
