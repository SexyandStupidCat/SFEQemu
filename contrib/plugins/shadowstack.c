/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * shadowstack 插件（linux-user）：基于“指令字节最小解码”识别 call，并在宿主侧维护影子调用栈。
 *
 * 设计摘要：
 * - 翻译阶段：遍历 TB 内指令字节，识别 call 指令，并在该指令上注册执行回调（携带 callsite/ret_addr）。
 * - 执行阶段：
 *   - TB 入口回调：用当前 TB 起始地址匹配 ret_addr 来弹栈；并在需要时把上一条 call 的目标函数入口
 *     记录为“下一段 TB 的起始地址”（pending_call -> commit）。
 *   - call 指令回调：压入 ret_addr，并标记 pending_call，等待下一 TB 提交 callee。
 *
 * 目前支持：aarch64、x86_64（仅限 linux-user；system emulation 会直接拒绝加载）。
 */

#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef enum {
    ARCH_UNKNOWN = 0,
    ARCH_AARCH64,
    ARCH_X86_64,
} Arch;

typedef struct {
    uint64_t callsite;
    uint64_t ret_addr;
} CallInfo;

typedef struct {
    uint64_t callsite;
    uint64_t ret_addr;
    uint64_t callee;
} StackFrame;

typedef struct {
    GArray *stack;              /* StackFrame[] */
    bool pending_call;
    uint64_t pending_ret_addr;
    uint64_t calls;
    uint64_t rets;
    uint64_t max_depth;
} VcpuState;

static Arch arch;
static struct qemu_plugin_scoreboard *states;

static GMutex callinfo_lock;
static GHashTable *callinfo_by_callsite; /* key: &CallInfo.callsite, val: CallInfo* */

static bool opt_log;
static bool opt_summary = true;
static uint32_t opt_unwind_limit = 10;
static uint32_t opt_max_stack = 0; /* 0 表示不限制 */

static inline uint32_t read_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static inline uint32_t read_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
        | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8)
        | (uint32_t)p[3];
}

static inline uint64_t calc_ret_addr(uint64_t callsite, size_t insn_len)
{
    return callsite + insn_len;
}

static bool aarch64_is_call_word(uint32_t insn)
{
    /* BL imm26: 1 00101 imm26 */
    if ((insn & 0xFC000000u) == 0x94000000u) {
        return true;
    }

    /*
     * 来自 target/arm/tcg/a64.decode 的关键模式：
     * - BLR:   1101011 0001 11111 000000 rn:5 00000
     * - BLRAZ: 1101011 0001 11111 00001  m:1 rn:5 11111   (BLRAAZ/BLRABZ)
     * - BLRA:  1101011 1001 11111 00001  m:1 rn:5 rm:5   (BLRAA/BLRAB)
     */

    uint32_t op31_25 = (insn >> 25) & 0x7Fu;
    uint32_t op24_21 = (insn >> 21) & 0x0Fu;
    uint32_t op20_16 = (insn >> 16) & 0x1Fu;

    if (op31_25 != 0x6Bu || op20_16 != 0x1Fu) {
        return false;
    }

    if (op24_21 == 0x1u) {
        /* BLR 或 BLRAZ */
        uint32_t op15_11 = (insn >> 11) & 0x1Fu;
        uint32_t op15_10 = (insn >> 10) & 0x3Fu;
        uint32_t op4_0 = insn & 0x1Fu;

        /* BLR: op15_10=0, op4_0=0 */
        if (op15_10 == 0x00u && op4_0 == 0x00u) {
            return true;
        }

        /* BLRAZ: op15_11=1, op4_0=31 */
        if (op15_11 == 0x01u && op4_0 == 0x1Fu) {
            return true;
        }

        return false;
    }

    if (op24_21 == 0x9u) {
        /* BLRA: op15_11=1 */
        uint32_t op15_11 = (insn >> 11) & 0x1Fu;
        return op15_11 == 0x01u;
    }

    return false;
}

static bool aarch64_is_call(const uint8_t *data, size_t len)
{
    if (len != 4) {
        return false;
    }

    /* 同时尝试 LE/BE，避免 target_name 无法区分 endian 的情况 */
    uint32_t w_le = read_u32_le(data);
    uint32_t w_be = read_u32_be(data);
    return aarch64_is_call_word(w_le) || aarch64_is_call_word(w_be);
}

static bool x86_64_is_prefix(uint8_t b)
{
    /* legacy 前缀 + REX（0x40-0x4F） */
    if ((b >= 0x40 && b <= 0x4F) ||
        b == 0xF0 || b == 0xF2 || b == 0xF3 ||
        b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
        b == 0x64 || b == 0x65 ||
        b == 0x66 || b == 0x67) {
        return true;
    }
    return false;
}

static bool x86_64_is_call(const uint8_t *data, size_t len)
{
    if (len == 0) {
        return false;
    }

    size_t i = 0;
    while (i < len && x86_64_is_prefix(data[i])) {
        i++;
    }
    if (i >= len) {
        return false;
    }

    uint8_t op = data[i];
    switch (op) {
    case 0xE8: /* call rel32 */
    case 0x9A: /* lcall ptr16:16/32（x86_64 下基本不会出现，但保守识别） */
        return true;
    case 0xFF: { /* group 5：/2 near call, /3 far call */
        if (i + 1 >= len) {
            return false;
        }
        uint8_t modrm = data[i + 1];
        uint8_t reg = (modrm >> 3) & 0x7;
        return reg == 2 || reg == 3;
    }
    default:
        return false;
    }
}

static bool is_call_insn(const uint8_t *data, size_t len)
{
    switch (arch) {
    case ARCH_AARCH64:
        return aarch64_is_call(data, len);
    case ARCH_X86_64:
        return x86_64_is_call(data, len);
    default:
        return false;
    }
}

static VcpuState *vcpu_state(unsigned int vcpu_index)
{
    VcpuState *s = qemu_plugin_scoreboard_find(states, vcpu_index);
    if (!s->stack) {
        s->stack = g_array_new(false, true, sizeof(StackFrame));
    }
    return s;
}

static CallInfo *callinfo_get(uint64_t callsite, uint64_t ret_addr)
{
    CallInfo *ci;

    g_mutex_lock(&callinfo_lock);
    ci = g_hash_table_lookup(callinfo_by_callsite, &callsite);
    if (!ci) {
        ci = g_new0(CallInfo, 1);
        ci->callsite = callsite;
        ci->ret_addr = ret_addr;
        g_hash_table_insert(callinfo_by_callsite, &ci->callsite, ci);
    }
    g_mutex_unlock(&callinfo_lock);

    return ci;
}

static void on_call_exec(unsigned int vcpu_index, void *userdata)
{
    const CallInfo *ci = (const CallInfo *)userdata;
    VcpuState *s = vcpu_state(vcpu_index);

    if (opt_max_stack && s->stack->len >= opt_max_stack) {
        return;
    }

    StackFrame frame = {
        .callsite = ci->callsite,
        .ret_addr = ci->ret_addr,
        .callee = 0,
    };
    g_array_append_val(s->stack, frame);

    s->pending_call = true;
    s->pending_ret_addr = ci->ret_addr;
    s->calls++;
    s->max_depth = MAX(s->max_depth, (uint64_t)s->stack->len);

    if (opt_log) {
        g_autoptr(GString) msg = g_string_new(NULL);
        g_string_printf(msg,
                        "CPU%u CALL @0x%" PRIx64 " ret=0x%" PRIx64 " depth=%u\n",
                        vcpu_index, ci->callsite, ci->ret_addr, s->stack->len);
        qemu_plugin_outs(msg->str);
    }
}

static void pop_to_match(VcpuState *s, unsigned int vcpu_index, uint64_t pc)
{
    if (s->stack->len == 0) {
        return;
    }

    size_t len = s->stack->len;
    size_t min_i = (opt_unwind_limit && opt_unwind_limit < len)
                       ? (len - opt_unwind_limit)
                       : 0;

    gssize match = -1;
    for (gssize i = (gssize)len - 1; i >= (gssize)min_i; --i) {
        const StackFrame *f = &g_array_index(s->stack, StackFrame, (guint)i);
        if (f->ret_addr == pc) {
            match = i;
            break;
        }
    }
    if (match < 0) {
        return;
    }

    for (size_t j = len; j > (size_t)match; --j) {
        const StackFrame *f = &g_array_index(s->stack, StackFrame, (guint)(j - 1));

        if (s->pending_call && f->ret_addr == s->pending_ret_addr) {
            s->pending_call = false;
            s->pending_ret_addr = 0;
        }

        s->rets++;
        if (opt_log) {
            g_autoptr(GString) msg = g_string_new(NULL);
            g_string_printf(msg,
                            "CPU%u RET  @0x%" PRIx64 " <- 0x%" PRIx64
                            " (call@0x%" PRIx64 ") depth=%u\n",
                            vcpu_index, pc, f->callee, f->callsite, (guint)(j - 1));
            qemu_plugin_outs(msg->str);
        }
    }

    g_array_set_size(s->stack, (guint)match);
}

static void commit_pending_call(VcpuState *s, unsigned int vcpu_index, uint64_t pc)
{
    if (!s->pending_call) {
        return;
    }

    if (s->stack->len == 0) {
        s->pending_call = false;
        s->pending_ret_addr = 0;
        return;
    }

    StackFrame *top = &g_array_index(s->stack, StackFrame, s->stack->len - 1);
    if (top->ret_addr == s->pending_ret_addr && top->callee == 0) {
        top->callee = pc;
        if (opt_log) {
            g_autoptr(GString) msg = g_string_new(NULL);
            g_string_printf(msg,
                            "CPU%u CALL_COMMIT call@0x%" PRIx64 " -> 0x%" PRIx64
                            " ret=0x%" PRIx64 " depth=%u\n",
                            vcpu_index, top->callsite, top->callee, top->ret_addr,
                            s->stack->len);
            qemu_plugin_outs(msg->str);
        }
    } else {
        if (opt_log) {
            g_autoptr(GString) msg = g_string_new(NULL);
            g_string_printf(msg,
                            "CPU%u CALL_COMMIT_STALE pc=0x%" PRIx64 "\n",
                            vcpu_index, pc);
            qemu_plugin_outs(msg->str);
        }
    }

    s->pending_call = false;
    s->pending_ret_addr = 0;
}

static void on_tb_exec(unsigned int vcpu_index, void *userdata)
{
    uint64_t pc = (uint64_t)(uintptr_t)userdata;
    VcpuState *s = vcpu_state(vcpu_index);

    /* 先处理 return（按 ret_addr 匹配，最多向下搜索 opt_unwind_limit 层） */
    pop_to_match(s, vcpu_index, pc);

    /* 再提交上一条 call 的目标（callee=当前 TB 起始地址） */
    commit_pending_call(s, vcpu_index, pc);
}

static void on_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;

    uint64_t tb_start = qemu_plugin_tb_vaddr(tb);
    g_assert(tb_start <= UINTPTR_MAX);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, on_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)(uintptr_t)tb_start);

    uint8_t stack_buf[16];

    size_t n_insns = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
        size_t len = qemu_plugin_insn_size(insn);

        uint8_t *buf = stack_buf;
        if (len > sizeof(stack_buf)) {
            buf = g_malloc(len);
        }
        qemu_plugin_insn_data(insn, buf, len);

        if (is_call_insn(buf, len)) {
            uint64_t ret_addr = calc_ret_addr(vaddr, len);
            CallInfo *ci = callinfo_get(vaddr, ret_addr);
            qemu_plugin_register_vcpu_insn_exec_cb(insn, on_call_exec,
                                                   QEMU_PLUGIN_CB_NO_REGS, ci);
        }

        if (buf != stack_buf) {
            g_free(buf);
        }
    }
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    (void)id;
    (void)vcpu_state(vcpu_index);
}

static void vcpu_exit(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    (void)id;
    VcpuState *s = qemu_plugin_scoreboard_find(states, vcpu_index);
    if (s->stack) {
        g_array_free(s->stack, true);
        s->stack = NULL;
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    (void)id;
    (void)p;

    if (opt_summary) {
        g_autoptr(GString) out = g_string_new("");
        for (int i = 0; i < qemu_plugin_num_vcpus(); ++i) {
            VcpuState *s = qemu_plugin_scoreboard_find(states, i);
            g_string_append_printf(out,
                                   "CPU%d: calls=%" PRIu64 " rets=%" PRIu64
                                   " max_depth=%" PRIu64 " depth=%u\n",
                                   i, s->calls, s->rets, s->max_depth,
                                   s->stack ? s->stack->len : 0);
        }
        qemu_plugin_outs(out->str);
    }

    for (int i = 0; i < qemu_plugin_num_vcpus(); ++i) {
        vcpu_exit(id, i);
    }

    qemu_plugin_scoreboard_free(states);
    states = NULL;

    g_mutex_lock(&callinfo_lock);
    if (callinfo_by_callsite) {
        g_hash_table_destroy(callinfo_by_callsite);
        callinfo_by_callsite = NULL;
    }
    g_mutex_unlock(&callinfo_lock);
}

static void usage(FILE *f)
{
    fprintf(f,
            "用法: -plugin <本插件>,[log=on|off],[summary=on|off],"
            "[unwind_limit=N],[max_stack=N]\n");
}

static bool parse_u32(const char *name, const char *val, uint32_t *out)
{
    if (!val || !*val) {
        return false;
    }
    char *end = NULL;
    unsigned long long tmp = strtoull(val, &end, 0);
    if (!end || *end != '\0' || tmp > UINT32_MAX) {
        fprintf(stderr, "plugin shadowstack: %s=%s 解析失败\n", name, val);
        return false;
    }
    *out = (uint32_t)tmp;
    return true;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    if (info->system_emulation) {
        fprintf(stderr, "plugin shadowstack: 仅支持 linux-user（非 system emulation）\n");
        return 1;
    }

    if (!strcmp(info->target_name, "aarch64")) {
        arch = ARCH_AARCH64;
    } else if (!strcmp(info->target_name, "x86_64")) {
        arch = ARCH_X86_64;
    } else {
        fprintf(stderr, "plugin shadowstack: 不支持的 target=%s\n",
                info->target_name);
        return 1;
    }

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        const char *k = tokens[0];
        const char *v = tokens[1];

        if (g_strcmp0(k, "log") == 0) {
            if (!qemu_plugin_bool_parse(k, v, &opt_log)) {
                fprintf(stderr, "plugin shadowstack: boolean 参数解析失败: %s\n", opt);
                return -1;
            }
        } else if (g_strcmp0(k, "summary") == 0) {
            if (!qemu_plugin_bool_parse(k, v, &opt_summary)) {
                fprintf(stderr, "plugin shadowstack: boolean 参数解析失败: %s\n", opt);
                return -1;
            }
        } else if (g_strcmp0(k, "unwind_limit") == 0) {
            if (!parse_u32(k, v, &opt_unwind_limit)) {
                return -1;
            }
        } else if (g_strcmp0(k, "max_stack") == 0) {
            if (!parse_u32(k, v, &opt_max_stack)) {
                return -1;
            }
        } else if (opt && *opt) {
            fprintf(stderr, "plugin shadowstack: 未知参数: %s\n", opt);
            usage(stderr);
            return -1;
        }
    }

    g_mutex_init(&callinfo_lock);
    callinfo_by_callsite = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                                 NULL, g_free);

    states = qemu_plugin_scoreboard_new(sizeof(VcpuState));

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_vcpu_exit_cb(id, vcpu_exit);
    qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
