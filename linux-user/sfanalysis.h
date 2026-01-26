#ifndef LINUX_USER_SFANALYSIS_H
#define LINUX_USER_SFANALYSIS_H

#include "qemu/osdep.h"
#include "user/abitypes.h"

typedef struct CPUState CPUState;
typedef struct Error Error;

typedef struct SfAnalysisResolved {
    uint64_t guest_addr;          /* 输入：guest 虚拟地址 */

    char *map_path;              /* /proc/self/maps 命中的映射路径（需要释放） */
    uint64_t map_start_guest;     /* 命中段起始（guest 视角） */
    uint64_t map_offset_file;     /* 命中段对应文件偏移（/proc/self/maps offset） */

    uint64_t load_bias_guest;     /* guest_addr - load_bias = 分析地址（Ghidra 地址） */
    uint64_t analysis_addr;       /* 用于查询 JSON 的地址（通常为 ELF p_vaddr） */

    const char *module_name;      /* SFAnalysis: file.name */
    const char *module_real_path; /* SFAnalysis: file.real_path */

    const char *func_name;
    const char *func_prototype;
    uint64_t func_entry;
    uint64_t func_size;
    uint64_t func_offset;

    const char *pseudocode_file;  /* SFAnalysis: pseudocode_file */
    char *pseudocode;             /* 伪 C 内容前缀（需要释放，可为空） */
    bool pseudocode_truncated;
} SfAnalysisResolved;

int sfanalysis_init(const char *out_dir, Error **errp);
bool sfanalysis_is_enabled(void);
void sfanalysis_cleanup(void);

int sfanalysis_resolve_guest_addr(CPUState *cpu, abi_ulong guest_addr,
                                  size_t max_pseudocode_bytes,
                                  SfAnalysisResolved *out);
int sfanalysis_resolve_host_addr(uint64_t host_addr,
                                 size_t max_pseudocode_bytes,
                                 SfAnalysisResolved *out);
void sfanalysis_resolved_cleanup(SfAnalysisResolved *res);

#endif /* LINUX_USER_SFANALYSIS_H */
