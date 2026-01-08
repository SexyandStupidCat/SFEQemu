/*
 * Generic intermediate code generation.
 *
 * Copyright (C) 2016-2017 Lluís Vilanova <vilanova@ac.upc.edu>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "accel/tcg/cpu-ldst-common.h"
#include "accel/tcg/cpu-mmu-index.h"
#include "exec/target_page.h"
#include "exec/translator.h"
#include "exec/plugin-gen.h"
#include "exec/shadowstack.h"
#include "tcg/tcg-op-common.h"
#ifdef CONFIG_USER_ONLY
#include "tcg/tcg-temp-internal.h"
#endif
#include "internal-common.h"
#include "disas/disas.h"
#include "tb-internal.h"

#ifdef CONFIG_USER_ONLY
static TCGHelperInfo shadowstack_info_tb_exec = {
    .flags = TCG_CALL_NO_RWG,
    .typemask = (dh_typemask(void, 0) |
                 dh_typemask(i32, 1) |
                 dh_typemask(i64, 2)),
};

static TCGHelperInfo shadowstack_info_call_exec = {
    .flags = TCG_CALL_NO_RWG,
    .typemask = (dh_typemask(void, 0) |
                 dh_typemask(i32, 1) |
                 dh_typemask(i64, 2) |
                 dh_typemask(i64, 3)),
};

static TCGv_i32 shadowstack_gen_cpu_index(CPUState *cpu)
{
    if (!tcg_cflags_has(cpu, CF_PARALLEL)) {
        return tcg_constant_i32(cpu->cpu_index);
    }
    TCGv_i32 cpu_index = tcg_temp_new_i32();
    tcg_gen_ld_i32(cpu_index, tcg_env,
                   offsetof(CPUState, cpu_index) - sizeof(CPUState));
    return cpu_index;
}

static void shadowstack_gen_tb_exec(CPUState *cpu, vaddr pc)
{
    TCGv_i32 cpu_index = shadowstack_gen_cpu_index(cpu);
    TCGv_i64 pc64 = tcg_constant_i64((uint64_t)pc);

    tcg_gen_call2(shadowstack_helper_tb_exec, &shadowstack_info_tb_exec, NULL,
                  tcgv_i32_temp(cpu_index),
                  tcgv_i64_temp(pc64));

    tcg_temp_free_i32(cpu_index);
    tcg_temp_free_i64(pc64);
}

static void shadowstack_gen_call_exec(CPUState *cpu, uint64_t callsite,
                                      uint64_t ret_addr)
{
    TCGv_i32 cpu_index = shadowstack_gen_cpu_index(cpu);
    TCGv_i64 callsite64 = tcg_constant_i64(callsite);
    TCGv_i64 ret64 = tcg_constant_i64(ret_addr);

    tcg_gen_call3(shadowstack_helper_call_exec, &shadowstack_info_call_exec,
                  NULL,
                  tcgv_i32_temp(cpu_index),
                  tcgv_i64_temp(callsite64),
                  tcgv_i64_temp(ret64));

    tcg_temp_free_i32(cpu_index);
    tcg_temp_free_i64(callsite64);
    tcg_temp_free_i64(ret64);
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

static bool aarch64_is_call_insn(CPUArchState *env, DisasContextBase *db,
                                 vaddr pc)
{
    uint8_t b0 = translator_ldub(env, db, pc + 0);
    uint8_t b1 = translator_ldub(env, db, pc + 1);
    uint8_t b2 = translator_ldub(env, db, pc + 2);
    uint8_t b3 = translator_ldub(env, db, pc + 3);

    uint32_t w_le = (uint32_t)b0 |
                    ((uint32_t)b1 << 8) |
                    ((uint32_t)b2 << 16) |
                    ((uint32_t)b3 << 24);
    uint32_t w_be = ((uint32_t)b0 << 24) |
                    ((uint32_t)b1 << 16) |
                    ((uint32_t)b2 << 8) |
                    (uint32_t)b3;

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

static bool x86_64_decode_call(CPUArchState *env, DisasContextBase *db,
                               vaddr pc, size_t *insn_len)
{
    size_t i = 0;
    while (i < 15 && x86_64_is_prefix(translator_ldub(env, db, pc + i))) {
        i++;
    }
    if (i >= 15) {
        return false;
    }

    uint8_t op = translator_ldub(env, db, pc + i);
    if (op == 0xE8) {
        /* call rel32 */
        size_t len = i + 1 + 4;
        if (len > 15) {
            return false;
        }
        *insn_len = len;
        return true;
    }

    if (op == 0xFF) {
        /* group 5：/2 near call, /3 far call */
        uint8_t modrm = translator_ldub(env, db, pc + i + 1);
        uint8_t reg = (modrm >> 3) & 0x7;
        if (reg != 2 && reg != 3) {
            return false;
        }

        size_t len = i + 2; /* opcode + modrm */
        if (len > 15) {
            return false;
        }
        uint8_t mod = (modrm >> 6) & 0x3;
        uint8_t rm = modrm & 0x7;

        bool has_sib = (mod != 3 && rm == 4);
        uint8_t sib = 0;
        if (has_sib) {
            if (len >= 15) {
                return false;
            }
            sib = translator_ldub(env, db, pc + len);
            len++;
        }

        if (mod == 0) {
            if (rm == 5) {
                len += 4;
            } else if (has_sib && ((sib & 0x7) == 5)) {
                len += 4;
            }
        } else if (mod == 1) {
            len += 1;
        } else if (mod == 2) {
            len += 4;
        }

        if (len > 15) {
            return false;
        }
        *insn_len = len;
        return true;
    }

    return false;
}

static inline uint16_t shadowstack_ldu16(CPUArchState *env, DisasContextBase *db,
                                        vaddr pc, bool be)
{
    uint8_t b0 = translator_ldub(env, db, pc + 0);
    uint8_t b1 = translator_ldub(env, db, pc + 1);

    if (be) {
        return ((uint16_t)b0 << 8) | (uint16_t)b1;
    }
    return (uint16_t)b0 | ((uint16_t)b1 << 8);
}

static inline uint32_t shadowstack_ldu32(CPUArchState *env, DisasContextBase *db,
                                        vaddr pc, bool be)
{
    uint8_t b0 = translator_ldub(env, db, pc + 0);
    uint8_t b1 = translator_ldub(env, db, pc + 1);
    uint8_t b2 = translator_ldub(env, db, pc + 2);
    uint8_t b3 = translator_ldub(env, db, pc + 3);

    if (be) {
        return ((uint32_t)b0 << 24) |
               ((uint32_t)b1 << 16) |
               ((uint32_t)b2 << 8) |
               (uint32_t)b3;
    }
    return (uint32_t)b0 |
           ((uint32_t)b1 << 8) |
           ((uint32_t)b2 << 16) |
           ((uint32_t)b3 << 24);
}

static bool arm_a32_is_call_word(uint32_t insn)
{
    /* BL/BLX(imm): .... 1011 .... .... .... .... .... .... */
    if ((insn & 0x0F000000u) == 0x0B000000u) {
        return true;
    }

    /* BLX(r): .... 0001 0010 1111 1111 1111 0011 .... */
    if ((insn & 0x0FFFFFF0u) == 0x012FFF30u) {
        return true;
    }

    return false;
}

static bool arm_thumb_is_call(CPUArchState *env, DisasContextBase *db, vaddr pc,
                              bool be, size_t *insn_len)
{
    uint16_t hw1 = shadowstack_ldu16(env, db, pc, be);

    /* Thumb-16: BLX (register) */
    if ((hw1 & 0xFF87u) == 0x4780u) {
        *insn_len = 2;
        return true;
    }

    /*
     * Thumb-2 / Thumb-1 split BL/BLX 前缀：0b11110_xxx_xxx_xxx_xxx
     * 为避免在页尾错误预取下一页，跟随 QEMU 的保守策略：仅在后半字仍在同一页时读取。
     */
    if ((hw1 >> 11) == 0x1Eu) {
        vaddr page_start = pc & TARGET_PAGE_MASK;
        if (pc - page_start < TARGET_PAGE_SIZE - 3) {
            uint16_t hw2 = shadowstack_ldu16(env, db, pc + 2, be);
            /* 低半字 [15:14] == 0b11 表示 BL/BLX(imm) */
            if ((hw2 & 0xC000u) == 0xC000u) {
                *insn_len = 4;
                return true;
            }
        }
    }

    return false;
}

static bool mips_is_call_word(uint32_t insn)
{
    uint32_t op = insn >> 26;

    /* JAL */
    if (op == 3) {
        return true;
    }

    /* JALX */
    if (op == 0x1Du) {
        return true;
    }

    /* BLTZAL/BGEZAL/BLTZALL/BGEZALL (REGIMM) */
    if (op == 1) {
        uint32_t rt = (insn >> 16) & 0x1Fu;
        return rt == 0x10u || rt == 0x11u || rt == 0x12u || rt == 0x13u;
    }

    /* SPECIAL: JALR */
    if (op == 0) {
        uint32_t funct = insn & 0x3Fu;
        return funct == 9;
    }

    return false;
}
#endif /* CONFIG_USER_ONLY */

static void set_can_do_io(DisasContextBase *db, bool val)
{
    QEMU_BUILD_BUG_ON(sizeof_field(CPUState, neg.can_do_io) != 1);
    tcg_gen_st8_i32(tcg_constant_i32(val), tcg_env,
                    offsetof(CPUState, neg.can_do_io) - sizeof(CPUState));
}

bool translator_io_start(DisasContextBase *db)
{
    /*
     * Ensure that this instruction will be the last in the TB.
     * The target may override this to something more forceful.
     */
    if (db->is_jmp == DISAS_NEXT) {
        db->is_jmp = DISAS_TOO_MANY;
    }
    return true;
}

static TCGOp *gen_tb_start(DisasContextBase *db, uint32_t cflags)
{
    TCGv_i32 count = NULL;
    TCGOp *icount_start_insn = NULL;

    if ((cflags & CF_USE_ICOUNT) || !(cflags & CF_NOIRQ)) {
        count = tcg_temp_new_i32();
        tcg_gen_ld_i32(count, tcg_env,
                       offsetof(CPUState, neg.icount_decr.u32) -
                       sizeof(CPUState));
    }

    if (cflags & CF_USE_ICOUNT) {
        /*
         * We emit a sub with a dummy immediate argument. Keep the insn index
         * of the sub so that we later (when we know the actual insn count)
         * can update the argument with the actual insn count.
         */
        tcg_gen_sub_i32(count, count, tcg_constant_i32(0));
        icount_start_insn = tcg_last_op();
    }

    /*
     * Emit the check against icount_decr.u32 to see if we should exit
     * unless we suppress the check with CF_NOIRQ. If we are using
     * icount and have suppressed interruption the higher level code
     * should have ensured we don't run more instructions than the
     * budget.
     */
    if (cflags & CF_NOIRQ) {
        tcg_ctx->exitreq_label = NULL;
    } else {
        tcg_ctx->exitreq_label = gen_new_label();
        tcg_gen_brcondi_i32(TCG_COND_LT, count, 0, tcg_ctx->exitreq_label);
    }

    if (cflags & CF_USE_ICOUNT) {
        tcg_gen_st16_i32(count, tcg_env,
                         offsetof(CPUState, neg.icount_decr.u16.low) -
                         sizeof(CPUState));
    }

    return icount_start_insn;
}

static void gen_tb_end(const TranslationBlock *tb, uint32_t cflags,
                       TCGOp *icount_start_insn, int num_insns)
{
    if (cflags & CF_USE_ICOUNT) {
        /*
         * Update the num_insn immediate parameter now that we know
         * the actual insn count.
         */
        tcg_set_insn_param(icount_start_insn, 2,
                           tcgv_i32_arg(tcg_constant_i32(num_insns)));
    }

    if (tcg_ctx->exitreq_label) {
        gen_set_label(tcg_ctx->exitreq_label);
        tcg_gen_exit_tb(tb, TB_EXIT_REQUESTED);
    }
}

bool translator_is_same_page(const DisasContextBase *db, vaddr addr)
{
    return ((addr ^ db->pc_first) & TARGET_PAGE_MASK) == 0;
}

bool translator_use_goto_tb(DisasContextBase *db, vaddr dest)
{
    /* Suppress goto_tb if requested. */
    if (tb_cflags(db->tb) & CF_NO_GOTO_TB) {
        return false;
    }

    /* Check for the dest on the same page as the start of the TB.  */
    return translator_is_same_page(db, dest);
}

void translator_loop(CPUState *cpu, TranslationBlock *tb, int *max_insns,
                     vaddr pc, void *host_pc, const TranslatorOps *ops,
                     DisasContextBase *db)
{
    uint32_t cflags = tb_cflags(tb);
    TCGOp *icount_start_insn;
    TCGOp *first_insn_start = NULL;
    bool plugin_enabled;
#ifdef CONFIG_USER_ONLY
    bool shadowstack_enabled = false;
    ShadowStackArch shadowstack_arch_v = SHADOWSTACK_ARCH_UNKNOWN;
    CPUArchState *env = NULL;
    bool shadowstack_be = false;
    bool arm_thumb = false;
#endif

    /* Initialize DisasContext */
    db->tb = tb;
    db->pc_first = pc;
    db->pc_next = pc;
    db->is_jmp = DISAS_NEXT;
    db->num_insns = 0;
    db->max_insns = *max_insns;
    db->insn_start = NULL;
    db->fake_insn = false;
    db->host_addr[0] = host_pc;
    db->host_addr[1] = NULL;
    db->record_start = 0;
    db->record_len = 0;
    db->code_mmuidx = cpu_mmu_index(cpu, true);

    ops->init_disas_context(db, cpu);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    /* Start translating.  */
    icount_start_insn = gen_tb_start(db, cflags);
    ops->tb_start(db, cpu);
    tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

    plugin_enabled = plugin_gen_tb_start(cpu, db);
    db->plugin_enabled = plugin_enabled;

#ifdef CONFIG_USER_ONLY
    shadowstack_enabled = shadowstack_is_enabled();
    if (shadowstack_enabled) {
        shadowstack_arch_v = shadowstack_arch();
        shadowstack_be = shadowstack_is_big_endian();
        env = cpu_env(cpu);
        if (shadowstack_arch_v == SHADOWSTACK_ARCH_ARM) {
            arm_thumb = ((tb->cs_base >> 23) & 1) != 0;
        }
        shadowstack_gen_tb_exec(cpu, db->pc_first);
    }
#endif

    while (true) {
        *max_insns = ++db->num_insns;
        ops->insn_start(db, cpu);
        db->insn_start = tcg_last_op();
        if (first_insn_start == NULL) {
            first_insn_start = db->insn_start;
        }
        tcg_debug_assert(db->is_jmp == DISAS_NEXT);  /* no early exit */

#ifdef CONFIG_USER_ONLY
        if (shadowstack_enabled) {
            vaddr pc_cur = db->pc_next;
            bool is_call = false;
            size_t insn_len = 0;

            if (shadowstack_arch_v == SHADOWSTACK_ARCH_AARCH64) {
                is_call = aarch64_is_call_insn(env, db, pc_cur);
                insn_len = 4;
            } else if (shadowstack_arch_v == SHADOWSTACK_ARCH_X86_64) {
                is_call = x86_64_decode_call(env, db, pc_cur, &insn_len);
            } else if (shadowstack_arch_v == SHADOWSTACK_ARCH_ARM) {
                if (!arm_thumb) {
                    uint32_t insn = shadowstack_ldu32(env, db, pc_cur,
                                                     shadowstack_be);
                    is_call = arm_a32_is_call_word(insn);
                    insn_len = 4;
                } else {
                    is_call = arm_thumb_is_call(env, db, pc_cur,
                                                shadowstack_be, &insn_len);
                }
            } else if (shadowstack_arch_v == SHADOWSTACK_ARCH_MIPS) {
                uint32_t insn = shadowstack_ldu32(env, db, pc_cur,
                                                 shadowstack_be);
                is_call = mips_is_call_word(insn);
                if (is_call) {
                    shadowstack_gen_call_exec(cpu, (uint64_t)pc_cur,
                                              (uint64_t)pc_cur + 8);
                }
                is_call = false;
            }

            if (is_call && insn_len) {
                shadowstack_gen_call_exec(cpu, (uint64_t)pc_cur,
                                          (uint64_t)pc_cur + insn_len);
            }
        }
#endif

        if (plugin_enabled) {
            plugin_gen_insn_start(cpu, db);
        }

        /*
         * Disassemble one instruction.  The translate_insn hook should
         * update db->pc_next and db->is_jmp to indicate what should be
         * done next -- either exiting this loop or locate the start of
         * the next instruction.
         */
        ops->translate_insn(db, cpu);

        /*
         * We can't instrument after instructions that change control
         * flow although this only really affects post-load operations.
         *
         * Calling plugin_gen_insn_end() before we possibly stop translation
         * is important. Even if this ends up as dead code, plugin generation
         * needs to see a matching plugin_gen_insn_{start,end}() pair in order
         * to accurately track instrumented helpers that might access memory.
         */
        if (plugin_enabled) {
            plugin_gen_insn_end();
        }

        /* Stop translation if translate_insn so indicated.  */
        if (db->is_jmp != DISAS_NEXT) {
            break;
        }

        /* Stop translation if the output buffer is full,
           or we have executed all of the allowed instructions.  */
        if (tcg_op_buf_full() || db->num_insns >= db->max_insns) {
            db->is_jmp = DISAS_TOO_MANY;
            break;
        }
    }

    /* Emit code to exit the TB, as indicated by db->is_jmp.  */
    ops->tb_stop(db, cpu);
    gen_tb_end(tb, cflags, icount_start_insn, db->num_insns);

    /*
     * Manage can_do_io for the translation block: set to false before
     * the first insn and set to true before the last insn.
     */
    if (db->num_insns == 1) {
        tcg_debug_assert(first_insn_start == db->insn_start);
    } else {
        tcg_debug_assert(first_insn_start != db->insn_start);
        tcg_ctx->emit_before_op = first_insn_start;
        set_can_do_io(db, false);
    }
    tcg_ctx->emit_before_op = db->insn_start;
    set_can_do_io(db, true);
    tcg_ctx->emit_before_op = NULL;

    /* May be used by disas_log or plugin callbacks. */
    tb->size = db->pc_next - db->pc_first;
    tb->icount = db->num_insns;

    if (plugin_enabled) {
        plugin_gen_tb_end(cpu, db->num_insns);
    }

    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)
        && qemu_log_in_addr_range(db->pc_first)) {
        FILE *logfile = qemu_log_trylock();
        if (logfile) {
            fprintf(logfile, "----------------\n");

            if (!ops->disas_log ||
                !ops->disas_log(db, cpu, logfile)) {
                fprintf(logfile, "IN: %s\n", lookup_symbol(db->pc_first));
                target_disas(logfile, cpu, db);
            }
            fprintf(logfile, "\n");
            qemu_log_unlock(logfile);
        }
    }
}

static bool translator_ld(CPUArchState *env, DisasContextBase *db,
                          void *dest, vaddr pc, size_t len)
{
    TranslationBlock *tb = db->tb;
    vaddr last = pc + len - 1;
    void *host;
    vaddr base;

    /* Use slow path if first page is MMIO. */
    if (unlikely(tb_page_addr0(tb) == -1)) {
        /* We capped translation with first page MMIO in tb_gen_code. */
        tcg_debug_assert(db->max_insns == 1);
        return false;
    }

    host = db->host_addr[0];
    base = db->pc_first;

    if (likely(((base ^ last) & TARGET_PAGE_MASK) == 0)) {
        /* Entire read is from the first page. */
        goto do_read;
    }

    if (unlikely(((base ^ pc) & TARGET_PAGE_MASK) == 0)) {
        /*
         * Read begins on the first page and extends to the second.
         * The unaligned read is never atomic.
         */
        size_t len0 = -(pc | TARGET_PAGE_MASK);
        memcpy(dest, host + (pc - base), len0);
        pc += len0;
        dest += len0;
        len -= len0;
    }

    /*
     * The read must conclude on the second page and not extend to a third.
     *
     * TODO: We could allow the two pages to be virtually discontiguous,
     * since we already allow the two pages to be physically discontiguous.
     * The only reasonable use case would be executing an insn at the end
     * of the address space wrapping around to the beginning.  For that,
     * we would need to know the current width of the address space.
     * In the meantime, assert.
     */
    base = (base & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
    assert(((base ^ pc) & TARGET_PAGE_MASK) == 0);
    assert(((base ^ last) & TARGET_PAGE_MASK) == 0);
    host = db->host_addr[1];

    if (host == NULL) {
        tb_page_addr_t page0, old_page1, new_page1;

        new_page1 = get_page_addr_code_hostp(env, base, &db->host_addr[1]);

        /*
         * If the second page is MMIO, treat as if the first page
         * was MMIO as well, so that we do not cache the TB.
         */
        if (unlikely(new_page1 == -1)) {
            tb_unlock_pages(tb);
            tb_set_page_addr0(tb, -1);
            /* Require that this be the final insn. */
            db->max_insns = db->num_insns;
            return false;
        }

        /*
         * If this is not the first time around, and page1 matches,
         * then we already have the page locked.  Alternately, we're
         * not doing anything to prevent the PTE from changing, so
         * we might wind up with a different page, requiring us to
         * re-do the locking.
         */
        old_page1 = tb_page_addr1(tb);
        if (likely(new_page1 != old_page1)) {
            page0 = tb_page_addr0(tb);
            if (unlikely(old_page1 != -1)) {
                tb_unlock_page1(page0, old_page1);
            }
            tb_set_page_addr1(tb, new_page1);
            tb_lock_page1(page0, new_page1);
        }
        host = db->host_addr[1];
    }

 do_read:
    /*
     * Assume aligned reads should be atomic, if possible.
     * We're not in a position to jump out with EXCP_ATOMIC.
     */
    host += pc - base;
    switch (len) {
    case 2:
        if (QEMU_IS_ALIGNED(pc, 2)) {
            uint16_t t = qatomic_read((uint16_t *)host);
            stw_he_p(dest, t);
            return true;
        }
        break;
    case 4:
        if (QEMU_IS_ALIGNED(pc, 4)) {
            uint32_t t = qatomic_read((uint32_t *)host);
            stl_he_p(dest, t);
            return true;
        }
        break;
#ifdef CONFIG_ATOMIC64
    case 8:
        if (QEMU_IS_ALIGNED(pc, 8)) {
            uint64_t t = qatomic_read__nocheck((uint64_t *)host);
            stq_he_p(dest, t);
            return true;
        }
        break;
#endif
    }
    /* Unaligned or partial read from the second page is not atomic. */
    memcpy(dest, host, len);
    return true;
}

static void record_save(DisasContextBase *db, vaddr pc,
                        const void *from, int size)
{
    int offset;

    /* Do not record probes before the start of TB. */
    if (pc < db->pc_first) {
        return;
    }

    /*
     * In translator_access, we verified that pc is within 2 pages
     * of pc_first, thus this will never overflow.
     */
    offset = pc - db->pc_first;

    /*
     * Either the first or second page may be I/O.  If it is the second,
     * then the first byte we need to record will be at a non-zero offset.
     * In either case, we should not need to record but a single insn.
     */
    if (db->record_len == 0) {
        db->record_start = offset;
        db->record_len = size;
    } else {
        assert(offset == db->record_start + db->record_len);
        assert(db->record_len + size <= sizeof(db->record));
        db->record_len += size;
    }

    memcpy(db->record + (offset - db->record_start), from, size);
}

size_t translator_st_len(const DisasContextBase *db)
{
    return db->fake_insn ? db->record_len : db->tb->size;
}

bool translator_st(const DisasContextBase *db, void *dest,
                   vaddr addr, size_t len)
{
    size_t offset, offset_end;

    if (addr < db->pc_first) {
        return false;
    }
    offset = addr - db->pc_first;
    offset_end = offset + len;
    if (offset_end > translator_st_len(db)) {
        return false;
    }

    if (!db->fake_insn) {
        size_t offset_page1 = -(db->pc_first | TARGET_PAGE_MASK);

        /* Get all the bytes from the first page. */
        if (db->host_addr[0]) {
            if (offset_end <= offset_page1) {
                memcpy(dest, db->host_addr[0] + offset, len);
                return true;
            }
            if (offset < offset_page1) {
                size_t len0 = offset_page1 - offset;
                memcpy(dest, db->host_addr[0] + offset, len0);
                offset += len0;
                dest += len0;
            }
        }

        /* Get any bytes from the second page. */
        if (db->host_addr[1] && offset >= offset_page1) {
            memcpy(dest, db->host_addr[1] + (offset - offset_page1),
                   offset_end - offset);
            return true;
        }
    }

    /* Else get recorded bytes. */
    if (db->record_len != 0 &&
        offset >= db->record_start &&
        offset_end <= db->record_start + db->record_len) {
        memcpy(dest, db->record + (offset - db->record_start),
               offset_end - offset);
        return true;
    }
    return false;
}

uint8_t translator_ldub(CPUArchState *env, DisasContextBase *db, vaddr pc)
{
    uint8_t val;

    if (!translator_ld(env, db, &val, pc, sizeof(val))) {
        MemOpIdx oi = make_memop_idx(MO_UB, db->code_mmuidx);
        val = cpu_ldb_code_mmu(env, pc, oi, 0);
        record_save(db, pc, &val, sizeof(val));
    }
    return val;
}

uint16_t translator_lduw_end(CPUArchState *env, DisasContextBase *db,
                             vaddr pc, MemOp endian)
{
    uint16_t val;

    if (!translator_ld(env, db, &val, pc, sizeof(val))) {
        MemOpIdx oi = make_memop_idx(MO_UW, db->code_mmuidx);
        val = cpu_ldw_code_mmu(env, pc, oi, 0);
        record_save(db, pc, &val, sizeof(val));
    }
    if (endian & MO_BSWAP) {
        val = bswap16(val);
    }
    return val;
}

uint32_t translator_ldl_end(CPUArchState *env, DisasContextBase *db,
                            vaddr pc, MemOp endian)
{
    uint32_t val;

    if (!translator_ld(env, db, &val, pc, sizeof(val))) {
        MemOpIdx oi = make_memop_idx(MO_UL, db->code_mmuidx);
        val = cpu_ldl_code_mmu(env, pc, oi, 0);
        record_save(db, pc, &val, sizeof(val));
    }
    if (endian & MO_BSWAP) {
        val = bswap32(val);
    }
    return val;
}

uint64_t translator_ldq_end(CPUArchState *env, DisasContextBase *db,
                            vaddr pc, MemOp endian)
{
    uint64_t val;

    if (!translator_ld(env, db, &val, pc, sizeof(val))) {
        MemOpIdx oi = make_memop_idx(MO_UQ, db->code_mmuidx);
        val = cpu_ldq_code_mmu(env, pc, oi, 0);
        record_save(db, pc, &val, sizeof(val));
    }
    if (endian & MO_BSWAP) {
        val = bswap64(val);
    }
    return val;
}

void translator_fake_ld(DisasContextBase *db, const void *data, size_t len)
{
    db->fake_insn = true;
    record_save(db, db->pc_first, data, len);
}
