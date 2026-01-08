/*
 * qemu-user 内置 shadowstack：运行期状态与 helper 实现
 *
 * 该模块不依赖外部插件接口；TCG 翻译阶段会在 TB 入口与 call 指令处插桩调用本文件的 helper。
 */

#include "qemu/osdep.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include "exec/shadowstack.h"

typedef struct {
    uint64_t callsite;
    uint64_t ret_addr;
    uint64_t callee;
} StackFrame;

typedef struct {
    GArray *stack; /* StackFrame[] */
    bool pending_call;
    uint64_t pending_ret_addr;
    uint64_t calls;
    uint64_t rets;
    uint64_t max_depth;
} VcpuState;

typedef struct {
    bool enabled;
    bool log;
    bool summary;
    uint32_t unwind_limit;
    uint32_t max_stack; /* 0 表示不限制 */
    ShadowStackArch arch;
    bool big_endian;
} ShadowStackConfig;

static ShadowStackConfig ss_cfg = {
    .enabled = false,
    .log = false,
    .summary = true,
    .unwind_limit = 10,
    .max_stack = 0,
    .arch = SHADOWSTACK_ARCH_UNKNOWN,
    .big_endian = false,
};

static bool ss_atexit_registered;
static bool ss_lock_initialized;

static GMutex ss_states_lock;
static GHashTable *ss_states_by_cpu; /* key: GUINT_TO_POINTER(cpu_index), val: VcpuState* */

static __thread VcpuState *ss_tls_state;
static __thread uint32_t ss_tls_cpu_index;

static void vcpu_state_free(gpointer p)
{
    VcpuState *s = (VcpuState *)p;
    if (!s) {
        return;
    }
    if (s->stack) {
        g_array_free(s->stack, true);
        s->stack = NULL;
    }
    g_free(s);
}

static VcpuState *vcpu_state(uint32_t cpu_index)
{
    if (ss_tls_state && ss_tls_cpu_index == cpu_index) {
        return ss_tls_state;
    }

    g_mutex_lock(&ss_states_lock);
    if (!ss_states_by_cpu) {
        ss_states_by_cpu = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                                 NULL, vcpu_state_free);
    }

    gpointer key = GUINT_TO_POINTER((guint)cpu_index);
    VcpuState *s = g_hash_table_lookup(ss_states_by_cpu, key);
    if (!s) {
        s = g_new0(VcpuState, 1);
        s->stack = g_array_new(false, true, sizeof(StackFrame));
        g_hash_table_insert(ss_states_by_cpu, key, s);
    }
    g_mutex_unlock(&ss_states_lock);

    ss_tls_state = s;
    ss_tls_cpu_index = cpu_index;
    return s;
}

static void pop_to_match(VcpuState *s, uint32_t cpu_index, uint64_t pc)
{
    if (!s->stack || s->stack->len == 0) {
        return;
    }

    size_t len = s->stack->len;
    size_t min_i = 0;
    if (ss_cfg.unwind_limit && ss_cfg.unwind_limit < len) {
        min_i = len - ss_cfg.unwind_limit;
    }

    gssize match = -1;
    for (gssize i = (gssize)len - 1; i >= (gssize)min_i; --i) {
        const StackFrame *f = &g_array_index(s->stack, StackFrame, (guint)i);
        if (f->ret_addr == pc ||
            (ss_cfg.arch == SHADOWSTACK_ARCH_MIPS && f->ret_addr == pc + 4)) {
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
        if (ss_cfg.log) {
            fprintf(stderr,
                    "CPU%" PRIu32 " RET  @0x%" PRIx64 " <- 0x%" PRIx64
                    " (call@0x%" PRIx64 ") depth=%u\n",
                    cpu_index, pc, f->callee, f->callsite, (unsigned)(j - 1));
        }
    }

    g_array_set_size(s->stack, (guint)match);
}

static void commit_pending_call(VcpuState *s, uint32_t cpu_index, uint64_t pc)
{
    if (!s->pending_call) {
        return;
    }

    if (!s->stack || s->stack->len == 0) {
        s->pending_call = false;
        s->pending_ret_addr = 0;
        return;
    }

    StackFrame *top = &g_array_index(s->stack, StackFrame, s->stack->len - 1);
    if (top->ret_addr == s->pending_ret_addr && top->callee == 0) {
        top->callee = pc;
        if (ss_cfg.log) {
            fprintf(stderr,
                    "CPU%" PRIu32 " CALL_COMMIT call@0x%" PRIx64 " -> 0x%" PRIx64
                    " ret=0x%" PRIx64 " depth=%u\n",
                    cpu_index, top->callsite, top->callee, top->ret_addr,
                    (unsigned)s->stack->len);
        }
    } else {
        if (ss_cfg.log) {
            fprintf(stderr,
                    "CPU%" PRIu32 " CALL_COMMIT_STALE pc=0x%" PRIx64 "\n",
                    cpu_index, pc);
        }
    }

    s->pending_call = false;
    s->pending_ret_addr = 0;
}

static bool parse_bool_opt(const char *name, const char *val, bool *out)
{
    if (!val || !*val) {
        return false;
    }
    if (!strcasecmp(val, "on") || !strcasecmp(val, "true") || !strcmp(val, "1") ||
        !strcasecmp(val, "yes")) {
        *out = true;
        return true;
    }
    if (!strcasecmp(val, "off") || !strcasecmp(val, "false") || !strcmp(val, "0") ||
        !strcasecmp(val, "no")) {
        *out = false;
        return true;
    }
    fprintf(stderr, "shadowstack: boolean 参数解析失败: %s=%s\n", name, val);
    return false;
}

static bool parse_u32_opt(const char *name, const char *val, uint32_t *out)
{
    if (!val || !*val) {
        return false;
    }
    char *end = NULL;
    unsigned long long tmp = strtoull(val, &end, 0);
    if (!end || *end != '\0' || tmp > UINT32_MAX) {
        fprintf(stderr, "shadowstack: %s=%s 解析失败\n", name, val);
        return false;
    }
    *out = (uint32_t)tmp;
    return true;
}

static gint cmp_cpu_index(gconstpointer a, gconstpointer b, gpointer user_data)
{
    (void)user_data;

    guint ai = GPOINTER_TO_UINT(a);
    guint bi = GPOINTER_TO_UINT(b);

    if (ai < bi) {
        return -1;
    }
    if (ai > bi) {
        return 1;
    }
    return 0;
}

static void shadowstack_atexit(void)
{
    if (!ss_cfg.enabled) {
        return;
    }

    g_mutex_lock(&ss_states_lock);
    if (ss_cfg.summary && ss_states_by_cpu) {
        GList *keys = g_hash_table_get_keys(ss_states_by_cpu);
        keys = g_list_sort_with_data(keys, cmp_cpu_index, NULL);

        for (GList *it = keys; it; it = it->next) {
            guint cpu_index = GPOINTER_TO_UINT(it->data);
            VcpuState *s = g_hash_table_lookup(ss_states_by_cpu, it->data);
            if (!s) {
                continue;
            }
            fprintf(stderr,
                    "CPU%u: calls=%" PRIu64 " rets=%" PRIu64
                    " max_depth=%" PRIu64 " depth=%u\n",
                    cpu_index, s->calls, s->rets, s->max_depth,
                    s->stack ? s->stack->len : 0);
        }
        g_list_free(keys);
    }

    if (ss_states_by_cpu) {
        g_hash_table_destroy(ss_states_by_cpu);
        ss_states_by_cpu = NULL;
    }
    g_mutex_unlock(&ss_states_lock);
}

int shadowstack_init_from_opts(const char *target_name, const char *optstr)
{
    ShadowStackConfig cfg = {
        .enabled = true,
        .log = false,
        .summary = true,
        .unwind_limit = 10,
        .max_stack = 0,
        .arch = SHADOWSTACK_ARCH_UNKNOWN,
        .big_endian = false,
    };

    if (target_name && !strcmp(target_name, "aarch64")) {
        cfg.arch = SHADOWSTACK_ARCH_AARCH64;
    } else if (target_name && !strcmp(target_name, "x86_64")) {
        cfg.arch = SHADOWSTACK_ARCH_X86_64;
    } else if (target_name &&
               (!strcmp(target_name, "arm") || !strcmp(target_name, "armeb"))) {
        cfg.arch = SHADOWSTACK_ARCH_ARM;
        cfg.big_endian = !strcmp(target_name, "armeb");
    } else if (target_name &&
               (!strcmp(target_name, "mips") || !strcmp(target_name, "mips64") ||
                !strcmp(target_name, "mipsn32"))) {
        cfg.arch = SHADOWSTACK_ARCH_MIPS;
        cfg.big_endian = true;
    } else if (target_name &&
               (!strcmp(target_name, "mipsel") || !strcmp(target_name, "mips64el") ||
                !strcmp(target_name, "mipsn32el"))) {
        cfg.arch = SHADOWSTACK_ARCH_MIPS;
        cfg.big_endian = false;
    } else {
        fprintf(stderr, "shadowstack: 不支持的 target=%s\n",
                target_name ? target_name : "(null)");
        return -1;
    }

    if (!optstr || !*optstr) {
        optstr = "on";
    }

    if (!strcmp(optstr, "off") || !strcmp(optstr, "0") ||
        !strcasecmp(optstr, "false")) {
        cfg.enabled = false;
    } else if (!strcmp(optstr, "on") || !strcmp(optstr, "1") ||
               !strcasecmp(optstr, "true")) {
        cfg.enabled = true;
    } else {
        g_auto(GStrv) tokens = g_strsplit(optstr, ",", -1);
        for (int i = 0; tokens && tokens[i]; i++) {
            const char *tok = tokens[i];
            if (!tok || !*tok) {
                continue;
            }

            char *eq = strchr(tok, '=');
            if (!eq) {
                if (!strcasecmp(tok, "on")) {
                    cfg.enabled = true;
                    continue;
                }
                if (!strcasecmp(tok, "off")) {
                    cfg.enabled = false;
                    continue;
                }
                fprintf(stderr, "shadowstack: 未知参数: %s\n", tok);
                return -1;
            }

            g_autofree char *k = g_strndup(tok, eq - tok);
            const char *v = eq + 1;

            if (!strcmp(k, "log")) {
                if (!parse_bool_opt(k, v, &cfg.log)) {
                    return -1;
                }
            } else if (!strcmp(k, "summary")) {
                if (!parse_bool_opt(k, v, &cfg.summary)) {
                    return -1;
                }
            } else if (!strcmp(k, "unwind_limit")) {
                if (!parse_u32_opt(k, v, &cfg.unwind_limit)) {
                    return -1;
                }
            } else if (!strcmp(k, "max_stack")) {
                if (!parse_u32_opt(k, v, &cfg.max_stack)) {
                    return -1;
                }
            } else {
                fprintf(stderr, "shadowstack: 未知参数: %s\n", tok);
                return -1;
            }
        }
    }

    ss_cfg = cfg;
    if (ss_cfg.enabled && !ss_atexit_registered) {
        if (!ss_lock_initialized) {
            ss_lock_initialized = true;
            g_mutex_init(&ss_states_lock);
        }
        ss_atexit_registered = true;
        atexit(shadowstack_atexit);
    }

    return 0;
}

bool shadowstack_is_enabled(void)
{
    return ss_cfg.enabled;
}

ShadowStackArch shadowstack_arch(void)
{
    return ss_cfg.arch;
}

bool shadowstack_is_big_endian(void)
{
    return ss_cfg.big_endian;
}

uint64_t *shadowstack_copy_ret_addrs(uint32_t cpu_index, size_t *out_len)
{
    if (out_len) {
        *out_len = 0;
    }
    if (!ss_cfg.enabled || !out_len) {
        return NULL;
    }

    VcpuState *s = vcpu_state(cpu_index);
    if (!s || !s->stack || s->stack->len == 0) {
        return NULL;
    }

    size_t n = s->stack->len;
    uint64_t *ret_addrs = g_new(uint64_t, n);
    for (size_t i = 0; i < n; i++) {
        const StackFrame *f = &g_array_index(s->stack, StackFrame, (guint)i);
        ret_addrs[i] = f->ret_addr;
    }
    *out_len = n;
    return ret_addrs;
}

void shadowstack_helper_call_exec(uint32_t cpu_index, uint64_t callsite,
                                  uint64_t ret_addr)
{
    if (!ss_cfg.enabled) {
        return;
    }

    VcpuState *s = vcpu_state(cpu_index);
    if (!s || !s->stack) {
        return;
    }

    if (ss_cfg.max_stack && s->stack->len >= ss_cfg.max_stack) {
        return;
    }

    StackFrame frame = {
        .callsite = callsite,
        .ret_addr = ret_addr,
        .callee = 0,
    };
    g_array_append_val(s->stack, frame);

    s->pending_call = true;
    s->pending_ret_addr = ret_addr;
    s->calls++;
    s->max_depth = MAX(s->max_depth, (uint64_t)s->stack->len);

    if (ss_cfg.log) {
        fprintf(stderr,
                "CPU%" PRIu32 " CALL @0x%" PRIx64 " ret=0x%" PRIx64 " depth=%u\n",
                cpu_index, callsite, ret_addr, (unsigned)s->stack->len);
    }
}

void shadowstack_helper_tb_exec(uint32_t cpu_index, uint64_t pc)
{
    if (!ss_cfg.enabled) {
        return;
    }

    VcpuState *s = vcpu_state(cpu_index);
    if (!s) {
        return;
    }

    pop_to_match(s, cpu_index, pc);
    commit_pending_call(s, cpu_index, pc);
}
