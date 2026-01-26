/*
 * SFAnalysis 输出接入：地址 -> (模块, 函数名, 伪C) 解析
 *
 * 设计目标：
 * - 启动时加载 SFAnalysis/out_* 目录下的 *.json（每个 ELF 对应一个 json）
 * - 运行时给定 guest 地址：
 *   1) 通过 g2h + /proc/self/maps 确认落在哪个映射段与文件路径
 *   2) 解析该 ELF 的 program header 计算 load_bias（适配 PIE/ET_EXEC）
 *   3) 用 (guest_addr - load_bias) 在 json functions[] 中二分查找函数
 *   4) 可选读取 pseudocode_file 的前缀内容
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/selfmap.h"
#include "qapi/error.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"
#include "qobject/qjson.h"

#include <elf.h>

#include "qemu.h"
#include "user-internals.h"

#include "sfanalysis.h"

typedef struct SfFuncInfo {
    uint64_t entry;
    uint64_t size;
    char *name;
    char *prototype;
    char *pseudocode_file;
} SfFuncInfo;

typedef struct SfModuleInfo {
    char *name;
    char *real_path;
    char *fs_root;
    char *rel_path; /* real_path 去掉 fs_root 后的相对路径（以 / 开头），可空 */

    SfFuncInfo *funcs;
    size_t n_funcs;
} SfModuleInfo;

typedef struct SfRuntimeCacheEntry {
    char *map_path;
    uint64_t load_bias_guest;
    bool load_bias_valid;
    SfModuleInfo *module;
} SfRuntimeCacheEntry;

typedef struct SfAnalysisDB {
    char *out_dir;
    GPtrArray *modules;               /* SfModuleInfo* */
    GHashTable *modules_by_real_path; /* key: real_path -> SfModuleInfo* */
    GHashTable *modules_by_rel_path;  /* key: rel_path  -> SfModuleInfo* */
    GHashTable *modules_by_basename;  /* key: basename  -> GPtrArray*(SfModuleInfo*) */

    GHashTable *runtime_cache;        /* key: map_path -> SfRuntimeCacheEntry* */
} SfAnalysisDB;

static GMutex sfdb_lock;
static SfAnalysisDB *sfdb;

/* /proc/self/maps 读取代价不小：短时间内多次解析（例如一次回溯多帧）时复用 */
#define SELFMAPS_CACHE_TTL_USEC 50000
static IntervalTreeRoot *selfmaps_cache_root;
static gint64 selfmaps_cache_ts_usec;

static void sf_func_info_free(SfFuncInfo *f)
{
    if (!f) {
        return;
    }
    g_free(f->name);
    g_free(f->prototype);
    g_free(f->pseudocode_file);
}

static void sf_module_info_free(SfModuleInfo *m)
{
    if (!m) {
        return;
    }
    for (size_t i = 0; i < m->n_funcs; i++) {
        sf_func_info_free(&m->funcs[i]);
    }
    g_free(m->funcs);
    g_free(m->name);
    g_free(m->real_path);
    g_free(m->fs_root);
    g_free(m->rel_path);
    g_free(m);
}

static void sf_runtime_cache_entry_free(gpointer data)
{
    SfRuntimeCacheEntry *e = data;
    if (!e) {
        return;
    }
    g_free(e->map_path);
    g_free(e);
}

static bool str_ends_with(const char *s, const char *suffix)
{
    size_t sl, sufl;
    if (!s || !suffix) {
        return false;
    }
    sl = strlen(s);
    sufl = strlen(suffix);
    if (sl < sufl) {
        return false;
    }
    return memcmp(s + sl - sufl, suffix, sufl) == 0;
}

static const char *path_basename(const char *path)
{
    const char *p;
    if (!path) {
        return NULL;
    }
    p = strrchr(path, '/');
    return p ? (p + 1) : path;
}

static char *strip_deleted_suffix(const char *path)
{
    const char *suffix = " (deleted)";
    size_t len;

    if (!path) {
        return NULL;
    }
    if (!str_ends_with(path, suffix)) {
        return g_strdup(path);
    }
    len = strlen(path) - strlen(suffix);
    return g_strndup(path, len);
}

static uint16_t read_u16(const uint8_t *p, bool be)
{
    return be ? (uint16_t)((p[0] << 8) | p[1]) : (uint16_t)((p[1] << 8) | p[0]);
}

static uint32_t read_u32(const uint8_t *p, bool be)
{
    if (be) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

static uint64_t read_u64(const uint8_t *p, bool be)
{
    uint64_t hi = read_u32(p + (be ? 0 : 4), be);
    uint64_t lo = read_u32(p + (be ? 4 : 0), be);
    return (hi << 32) | lo;
}

/*
 * 读取 ELF program header，找到覆盖 map_offset 的 PT_LOAD 段，
 * 返回该段的 (p_vaddr, p_offset)，用于计算 load_bias。
 */
static int elf_find_load_segment(const char *path, uint64_t map_offset,
                                 uint64_t *out_p_vaddr, uint64_t *out_p_offset)
{
    int fd;
    uint8_t ident[16];
    ssize_t n;
    bool be;
    uint8_t klass;
    uint64_t phoff;
    uint16_t phentsize, phnum;
    uint64_t best_p_vaddr = 0, best_p_offset = 0;
    uint64_t best_span = UINT64_MAX;
    bool found = false;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }

    n = pread(fd, ident, sizeof(ident), 0);
    if (n != (ssize_t)sizeof(ident)) {
        close(fd);
        return -EINVAL;
    }
    if (memcmp(ident, ELFMAG, SELFMAG) != 0) {
        close(fd);
        return -EINVAL;
    }

    klass = ident[EI_CLASS];
    be = (ident[EI_DATA] == ELFDATA2MSB);

    if (klass == ELFCLASS32) {
        uint8_t ehdr[52];
        n = pread(fd, ehdr, sizeof(ehdr), 0);
        if (n != (ssize_t)sizeof(ehdr)) {
            close(fd);
            return -EINVAL;
        }
        phoff = read_u32(ehdr + 28, be);
        phentsize = read_u16(ehdr + 42, be);
        phnum = read_u16(ehdr + 44, be);
    } else if (klass == ELFCLASS64) {
        uint8_t ehdr[64];
        n = pread(fd, ehdr, sizeof(ehdr), 0);
        if (n != (ssize_t)sizeof(ehdr)) {
            close(fd);
            return -EINVAL;
        }
        phoff = read_u64(ehdr + 32, be);
        phentsize = read_u16(ehdr + 54, be);
        phnum = read_u16(ehdr + 56, be);
    } else {
        close(fd);
        return -EINVAL;
    }

    if (phoff == 0 || phentsize == 0 || phnum == 0 || phnum > 4096) {
        close(fd);
        return -EINVAL;
    }

    for (uint16_t i = 0; i < phnum; i++) {
        uint8_t phdr_buf[64];
        uint64_t p_type, p_offset, p_vaddr, p_memsz;
        uint64_t span;
        off_t off = (off_t)(phoff + (uint64_t)i * phentsize);

        memset(phdr_buf, 0, sizeof(phdr_buf));
        n = pread(fd, phdr_buf, MIN((size_t)phentsize, sizeof(phdr_buf)), off);
        if (n < (ssize_t)MIN((size_t)phentsize, sizeof(phdr_buf))) {
            continue;
        }

        if (klass == ELFCLASS32) {
            p_type = read_u32(phdr_buf + 0, be);
            p_offset = read_u32(phdr_buf + 4, be);
            p_vaddr = read_u32(phdr_buf + 8, be);
            p_memsz = read_u32(phdr_buf + 20, be);
        } else {
            p_type = read_u32(phdr_buf + 0, be);
            p_offset = read_u64(phdr_buf + 8, be);
            p_vaddr = read_u64(phdr_buf + 16, be);
            p_memsz = read_u64(phdr_buf + 40, be);
        }

        if (p_type != PT_LOAD) {
            continue;
        }

        if (map_offset < p_offset) {
            continue;
        }
        if (p_memsz == 0) {
            continue;
        }

        /*
         * /proc/self/maps 的 offset 是按页对齐的。
         * 这里使用“覆盖关系”匹配：map_offset 落在 [p_offset, p_offset+p_memsz)。
         * 再用最小 span 的段作为最佳匹配（避免多个 PT_LOAD 重叠时选错）。
         */
        if (map_offset >= p_offset && map_offset < p_offset + p_memsz) {
            span = p_memsz;
            if (span < best_span) {
                best_span = span;
                best_p_offset = p_offset;
                best_p_vaddr = p_vaddr;
                found = true;
            }
        }
    }

    close(fd);

    if (!found) {
        return -ENOENT;
    }

    *out_p_vaddr = best_p_vaddr;
    *out_p_offset = best_p_offset;
    return 0;
}

static int module_compute_load_bias_guest(const char *map_path,
                                         uint64_t map_start_guest,
                                         uint64_t map_offset_file,
                                         uint64_t *out_load_bias_guest)
{
    uint64_t p_vaddr, p_offset;
    uint64_t seg_vaddr_at_map_start;
    int rc;

    rc = elf_find_load_segment(map_path, map_offset_file, &p_vaddr, &p_offset);
    if (rc < 0) {
        return rc;
    }

    seg_vaddr_at_map_start = p_vaddr + (map_offset_file - p_offset);
    *out_load_bias_guest = map_start_guest - seg_vaddr_at_map_start;
    return 0;
}

static int func_entry_cmp(const void *a, const void *b)
{
    const SfFuncInfo *fa = a;
    const SfFuncInfo *fb = b;
    if (fa->entry < fb->entry) {
        return -1;
    }
    if (fa->entry > fb->entry) {
        return 1;
    }
    return 0;
}

static const SfFuncInfo *module_find_func(const SfModuleInfo *m, uint64_t addr)
{
    size_t lo = 0, hi;

    if (!m || !m->funcs || m->n_funcs == 0) {
        return NULL;
    }

    hi = m->n_funcs;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (m->funcs[mid].entry <= addr) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo == 0) {
        return NULL;
    }

    const SfFuncInfo *f = &m->funcs[lo - 1];
    if (f->size > 0) {
        if (addr < f->entry + f->size) {
            return f;
        }
        return NULL;
    }
    return (addr == f->entry) ? f : NULL;
}

static char *read_file_prefix(const char *path, size_t max_bytes, bool *out_trunc)
{
    int fd;
    struct stat st;
    ssize_t n;
    char *buf;
    bool trunc = false;

    if (!path || max_bytes == 0) {
        if (out_trunc) {
            *out_trunc = false;
        }
        return NULL;
    }

    /* 避免日志里塞太大内容导致性能/可用性问题 */
    if (max_bytes > (1024 * 1024)) {
        max_bytes = 1024 * 1024;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (out_trunc) {
            *out_trunc = false;
        }
        return NULL;
    }

    buf = g_malloc0(max_bytes + 1);
    n = read(fd, buf, max_bytes);
    if (n < 0) {
        close(fd);
        g_free(buf);
        if (out_trunc) {
            *out_trunc = false;
        }
        return NULL;
    }
    buf[n] = '\0';

    if (fstat(fd, &st) == 0 && (uint64_t)st.st_size > (uint64_t)n) {
        trunc = true;
    }
    close(fd);

    if (out_trunc) {
        *out_trunc = trunc;
    }
    return buf;
}

static void modules_by_basename_add(GHashTable *ht, const char *base, SfModuleInfo *m)
{
    GPtrArray *arr;

    if (!ht || !base || !m) {
        return;
    }

    arr = g_hash_table_lookup(ht, base);
    if (!arr) {
        arr = g_ptr_array_new();
        g_hash_table_insert(ht, g_strdup(base), arr);
    }
    g_ptr_array_add(arr, m);
}

static void modules_by_basename_free_value(gpointer data)
{
    GPtrArray *arr = data;
    if (arr) {
        g_ptr_array_free(arr, true);
    }
}

static SfModuleInfo *choose_best_basename_candidate(GPtrArray *arr, const char *map_path)
{
    if (!arr || arr->len == 0) {
        return NULL;
    }
    if (arr->len == 1 || !map_path) {
        return g_ptr_array_index(arr, 0);
    }

    /* 若存在 rel_path，优先匹配 map_path 以 rel_path 结尾的模块 */
    for (guint i = 0; i < arr->len; i++) {
        SfModuleInfo *m = g_ptr_array_index(arr, i);
        if (m->rel_path && str_ends_with(map_path, m->rel_path)) {
            return m;
        }
    }
    return g_ptr_array_index(arr, 0);
}

static SfModuleInfo *sfdb_find_module_by_map_path(SfAnalysisDB *db, const char *map_path)
{
    SfModuleInfo *m;
    char *clean;
    const char *base;
    GPtrArray *arr;

    if (!db || !map_path) {
        return NULL;
    }

    clean = strip_deleted_suffix(map_path);

    m = g_hash_table_lookup(db->modules_by_real_path, clean);
    if (m) {
        g_free(clean);
        return m;
    }

    base = path_basename(clean);
    if (base) {
        arr = g_hash_table_lookup(db->modules_by_basename, base);
        m = choose_best_basename_candidate(arr, clean);
        if (m) {
            g_free(clean);
            return m;
        }
    }

    /*
     * 最后尝试：如果 map_path 在某个 fs_root 下，但分析时 fs_root 不同，
     * 则可通过 “以 / 开头的相对路径” 做兜底匹配。
     */
    for (const char *p = clean; *p; p++) {
        if (*p == '/') {
            m = g_hash_table_lookup(db->modules_by_rel_path, p);
            if (m) {
                g_free(clean);
                return m;
            }
        }
    }

    g_free(clean);
    return NULL;
}

static SfModuleInfo *load_one_module_json(const char *json_path, Error **errp)
{
    g_autofree char *content = NULL;
    gsize len = 0;
    g_autoptr(QDict) root = NULL;
    QDict *file;
    const char *name, *real_path, *fs_root;
    QList *funcs_list;
    SfModuleInfo *m = NULL;
    size_t n_funcs = 0;
    SfFuncInfo *funcs = NULL;
    size_t cap = 0;
    const QListEntry *entry;

    if (!g_file_get_contents(json_path, &content, &len, NULL)) {
        return NULL;
    }

    root = qobject_to(QDict, qobject_from_json(content, errp));
    if (!root) {
        return NULL;
    }

    file = qdict_get_qdict(root, "file");
    if (!file) {
        return NULL;
    }

    name = qdict_get_try_str(file, "name");
    real_path = qdict_get_try_str(file, "real_path");
    fs_root = qdict_get_try_str(file, "fs_root");
    if (!name || !real_path) {
        return NULL;
    }

    funcs_list = qdict_get_qlist(root, "functions");
    if (!funcs_list) {
        return NULL;
    }

    QLIST_FOREACH_ENTRY(funcs_list, entry) {
        QDict *f = qobject_to(QDict, qlist_entry_obj(entry));
        QDict *entry_dict;
        const char *fname;
        const char *proto;
        const char *pseudofile;
        uint64_t off, size;
        int64_t size_i;

        if (!f) {
            continue;
        }
        fname = qdict_get_try_str(f, "name");
        proto = qdict_get_try_str(f, "prototype");
        pseudofile = qdict_get_try_str(f, "pseudocode_file");
        entry_dict = qdict_get_qdict(f, "entry");
        if (!fname || !entry_dict) {
            continue;
        }
        if (!qdict_haskey(entry_dict, "offset")) {
            continue;
        }

        off = qdict_get_uint(entry_dict, "offset");
        size_i = qdict_get_try_int(f, "size", 0);
        size = (size_i > 0) ? (uint64_t)size_i : 0;

        if (n_funcs == cap) {
            cap = cap ? cap * 2 : 1024;
            funcs = g_realloc_n(funcs, cap, sizeof(*funcs));
        }

        funcs[n_funcs].entry = off;
        funcs[n_funcs].size = size;
        funcs[n_funcs].name = g_strdup(fname);
        funcs[n_funcs].prototype = proto ? g_strdup(proto) : NULL;
        funcs[n_funcs].pseudocode_file = pseudofile ? g_strdup(pseudofile) : NULL;
        n_funcs++;
    }

    if (n_funcs == 0) {
        g_free(funcs);
        return NULL;
    }

    qsort(funcs, n_funcs, sizeof(*funcs), func_entry_cmp);

    m = g_new0(SfModuleInfo, 1);
    m->name = g_strdup(name);
    m->real_path = g_strdup(real_path);
    m->fs_root = fs_root ? g_strdup(fs_root) : NULL;
    m->funcs = funcs;
    m->n_funcs = n_funcs;

    if (m->fs_root && g_str_has_prefix(m->real_path, m->fs_root)) {
        const char *rel = m->real_path + strlen(m->fs_root);
        if (rel[0] == '\0') {
            m->rel_path = g_strdup("/");
        } else {
            m->rel_path = g_strdup(rel);
        }
    }

    return m;
}

static void sfanalysis_cleanup_locked(void)
{
    if (!sfdb) {
        return;
    }

    if (selfmaps_cache_root) {
        free_self_maps(selfmaps_cache_root);
        selfmaps_cache_root = NULL;
        selfmaps_cache_ts_usec = 0;
    }

    if (sfdb->runtime_cache) {
        g_hash_table_destroy(sfdb->runtime_cache);
    }
    if (sfdb->modules_by_basename) {
        g_hash_table_destroy(sfdb->modules_by_basename);
    }
    if (sfdb->modules_by_rel_path) {
        g_hash_table_destroy(sfdb->modules_by_rel_path);
    }
    if (sfdb->modules_by_real_path) {
        g_hash_table_destroy(sfdb->modules_by_real_path);
    }
    if (sfdb->modules) {
        for (guint i = 0; i < sfdb->modules->len; i++) {
            sf_module_info_free(g_ptr_array_index(sfdb->modules, i));
        }
        g_ptr_array_free(sfdb->modules, true);
    }
    g_free(sfdb->out_dir);
    g_free(sfdb);
    sfdb = NULL;
}

int sfanalysis_init(const char *out_dir, Error **errp)
{
    DIR *dir;
    struct dirent *de;

    g_mutex_lock(&sfdb_lock);
    if (sfdb) {
        g_mutex_unlock(&sfdb_lock);
        return 0;
    }

    if (!out_dir || out_dir[0] == '\0') {
        g_mutex_unlock(&sfdb_lock);
        return 0;
    }

    dir = opendir(out_dir);
    if (!dir) {
        error_setg_errno(errp, errno, "无法打开 SFAnalysis 输出目录: %s", out_dir);
        g_mutex_unlock(&sfdb_lock);
        return -errno;
    }

    sfdb = g_new0(SfAnalysisDB, 1);
    sfdb->out_dir = g_strdup(out_dir);
    sfdb->modules = g_ptr_array_new();
    sfdb->modules_by_real_path = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                       g_free, NULL);
    sfdb->modules_by_rel_path = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                      g_free, NULL);
    sfdb->modules_by_basename = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                      g_free, modules_by_basename_free_value);
    sfdb->runtime_cache = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                g_free, sf_runtime_cache_entry_free);

    while ((de = readdir(dir)) != NULL) {
        g_autofree char *json_path = NULL;
        g_autoptr(Error) local_err = NULL;
        SfModuleInfo *m;
        const char *base;

        if (de->d_name[0] == '.') {
            continue;
        }
        if (!str_ends_with(de->d_name, ".json")) {
            continue;
        }

        json_path = g_build_filename(out_dir, de->d_name, NULL);
        m = load_one_module_json(json_path, &local_err);
        if (!m) {
            continue;
        }

        g_ptr_array_add(sfdb->modules, m);
        g_hash_table_insert(sfdb->modules_by_real_path, g_strdup(m->real_path), m);
        if (m->rel_path) {
            g_hash_table_insert(sfdb->modules_by_rel_path, g_strdup(m->rel_path), m);
        }
        base = path_basename(m->real_path);
        if (base) {
            modules_by_basename_add(sfdb->modules_by_basename, base, m);
        }
    }

    closedir(dir);

    if (sfdb->modules->len == 0) {
        /* 没有可用模块：认为 init 失败，但不让整个 qemu 退出 */
        sfanalysis_cleanup_locked();
        error_setg(errp, "SFAnalysis 输出目录中未发现可用的 *.json: %s", out_dir);
        g_mutex_unlock(&sfdb_lock);
        return -ENOENT;
    }

    g_mutex_unlock(&sfdb_lock);
    return 0;
}

bool sfanalysis_is_enabled(void)
{
    bool ok;
    g_mutex_lock(&sfdb_lock);
    ok = (sfdb && sfdb->modules && sfdb->modules->len > 0);
    g_mutex_unlock(&sfdb_lock);
    return ok;
}

void sfanalysis_cleanup(void)
{
    g_mutex_lock(&sfdb_lock);
    sfanalysis_cleanup_locked();
    g_mutex_unlock(&sfdb_lock);
}

void sfanalysis_resolved_cleanup(SfAnalysisResolved *res)
{
    if (!res) {
        return;
    }
    g_free(res->map_path);
    g_free(res->pseudocode);
    memset(res, 0, sizeof(*res));
}

static int resolve_map_for_host(uint64_t host_addr, MapInfo **out_map)
{
    IntervalTreeRoot *root;
    IntervalTreeNode *n;
    MapInfo *mi;
    gint64 now;

    now = g_get_monotonic_time();
    root = selfmaps_cache_root;
    if (!root || now - selfmaps_cache_ts_usec > SELFMAPS_CACHE_TTL_USEC) {
        if (root) {
            free_self_maps(root);
        }
        root = read_self_maps();
        selfmaps_cache_root = root;
        selfmaps_cache_ts_usec = now;
    }
    if (!root) {
        return -EIO;
    }

    n = interval_tree_iter_first(root, host_addr, host_addr);
    if (!n) {
        return -ENOENT;
    }

    mi = container_of(n, MapInfo, itree);
    if (!mi->path || mi->path[0] == '\0' || mi->path[0] == '[') {
        return -ENOENT;
    }

    *out_map = g_memdup2(mi, sizeof(*mi));
    /* 注意：mi->path 指针指向 root 内部内存，后续会失效，必须拷贝 */
    (*out_map)->path = g_strdup(mi->path);
    return 0;
}

static int runtime_cache_get_or_create(SfAnalysisDB *db, const char *map_path,
                                      SfRuntimeCacheEntry **out_entry)
{
    SfRuntimeCacheEntry *e;

    e = g_hash_table_lookup(db->runtime_cache, map_path);
    if (e) {
        *out_entry = e;
        return 0;
    }

    e = g_new0(SfRuntimeCacheEntry, 1);
    e->map_path = g_strdup(map_path);
    e->load_bias_valid = false;
    e->module = NULL;

    g_hash_table_insert(db->runtime_cache, g_strdup(map_path), e);
    *out_entry = e;
    return 0;
}

int sfanalysis_resolve_guest_addr(CPUState *cpu, abi_ulong guest_addr,
                                  size_t max_pseudocode_bytes,
                                  SfAnalysisResolved *out)
{
    uint64_t host_addr;
    void *host_ptr;
    MapInfo *map = NULL;
    int rc;
    SfRuntimeCacheEntry *cache;
    SfModuleInfo *module;
    const SfFuncInfo *func;
    uint64_t map_start_guest, load_bias;
    uint64_t analysis_addr;
    uint64_t p_offset;

    if (!out) {
        return -EINVAL;
    }
    memset(out, 0, sizeof(*out));
    out->guest_addr = (uint64_t)guest_addr;

    g_mutex_lock(&sfdb_lock);
    if (!sfdb) {
        g_mutex_unlock(&sfdb_lock);
        return -ENOENT;
    }

    host_ptr = g2h(cpu, guest_addr);
    host_addr = (uint64_t)(uintptr_t)host_ptr;

    rc = resolve_map_for_host(host_addr, &map);
    if (rc < 0) {
        g_mutex_unlock(&sfdb_lock);
        return rc;
    }

    out->map_path = strip_deleted_suffix(map->path);
    out->map_offset_file = map->offset;

    if (!h2g_valid((void *)(uintptr_t)map->itree.start)) {
        g_free((char *)map->path);
        g_free(map);
        g_mutex_unlock(&sfdb_lock);
        return -EINVAL;
    }
    map_start_guest = (uint64_t)h2g((void *)(uintptr_t)map->itree.start);
    out->map_start_guest = map_start_guest;

    rc = runtime_cache_get_or_create(sfdb, out->map_path, &cache);
    if (rc < 0) {
        g_free((char *)map->path);
        g_free(map);
        g_mutex_unlock(&sfdb_lock);
        return rc;
    }

    if (!cache->module) {
        cache->module = sfdb_find_module_by_map_path(sfdb, out->map_path);
    }
    module = cache->module;

    if (!module) {
        g_free((char *)map->path);
        g_free(map);
        g_mutex_unlock(&sfdb_lock);
        return -ENOENT;
    }

    if (!cache->load_bias_valid) {
        p_offset = out->map_offset_file;
        rc = module_compute_load_bias_guest(out->map_path, map_start_guest, p_offset, &load_bias);
        if (rc < 0) {
            g_free((char *)map->path);
            g_free(map);
            g_mutex_unlock(&sfdb_lock);
            return rc;
        }
        cache->load_bias_guest = load_bias;
        cache->load_bias_valid = true;
    }

    load_bias = cache->load_bias_guest;
    analysis_addr = (uint64_t)guest_addr - load_bias;

    out->load_bias_guest = load_bias;
    out->analysis_addr = analysis_addr;
    out->module_name = module->name;
    out->module_real_path = module->real_path;

    func = module_find_func(module, analysis_addr);
    if (func) {
        out->func_name = func->name;
        out->func_prototype = func->prototype;
        out->func_entry = func->entry;
        out->func_size = func->size;
        out->func_offset = analysis_addr - func->entry;
        out->pseudocode_file = func->pseudocode_file;
        out->pseudocode = read_file_prefix(func->pseudocode_file, max_pseudocode_bytes,
                                           &out->pseudocode_truncated);
    }

    g_free((char *)map->path);
    g_free(map);
    g_mutex_unlock(&sfdb_lock);
    return 0;
}

int sfanalysis_resolve_host_addr(uint64_t host_addr,
                                 size_t max_pseudocode_bytes,
                                 SfAnalysisResolved *out)
{
    MapInfo *map = NULL;
    int rc;
    SfRuntimeCacheEntry *cache;
    SfModuleInfo *module;
    const SfFuncInfo *func;
    uint64_t map_start_host;
    uint64_t map_offset_file;
    uint64_t p_vaddr, p_offset;
    uint64_t seg_vaddr_at_map_start;
    uint64_t analysis_addr;

    if (!out) {
        return -EINVAL;
    }
    memset(out, 0, sizeof(*out));

    if (host_addr == 0) {
        return -EINVAL;
    }

    g_mutex_lock(&sfdb_lock);
    if (!sfdb) {
        g_mutex_unlock(&sfdb_lock);
        return -ENOENT;
    }

    rc = resolve_map_for_host(host_addr, &map);
    if (rc < 0) {
        g_mutex_unlock(&sfdb_lock);
        return rc;
    }

    out->map_path = strip_deleted_suffix(map->path);
    out->map_offset_file = map->offset;

    map_start_host = (uint64_t)map->itree.start;
    map_offset_file = out->map_offset_file;

    rc = runtime_cache_get_or_create(sfdb, out->map_path, &cache);
    if (rc < 0) {
        g_free((char *)map->path);
        g_free(map);
        g_mutex_unlock(&sfdb_lock);
        return rc;
    }

    if (!cache->module) {
        cache->module = sfdb_find_module_by_map_path(sfdb, out->map_path);
    }
    module = cache->module;
    if (!module) {
        g_free((char *)map->path);
        g_free(map);
        g_mutex_unlock(&sfdb_lock);
        return -ENOENT;
    }

    rc = elf_find_load_segment(out->map_path, map_offset_file, &p_vaddr, &p_offset);
    if (rc < 0) {
        g_free((char *)map->path);
        g_free(map);
        g_mutex_unlock(&sfdb_lock);
        return rc;
    }

    seg_vaddr_at_map_start = p_vaddr + (map_offset_file - p_offset);
    if (host_addr < map_start_host) {
        g_free((char *)map->path);
        g_free(map);
        g_mutex_unlock(&sfdb_lock);
        return -EINVAL;
    }

    analysis_addr = seg_vaddr_at_map_start + (host_addr - map_start_host);
    out->analysis_addr = analysis_addr;

    /* 尝试补齐 guest 视角信息（对非 guest mapping 可能失败） */
    if (h2g_valid((void *)(uintptr_t)host_addr)) {
        out->guest_addr = (uint64_t)h2g((void *)(uintptr_t)host_addr);
    }
    if (h2g_valid((void *)(uintptr_t)map_start_host)) {
        out->map_start_guest = (uint64_t)h2g((void *)(uintptr_t)map_start_host);
    }

    if (out->guest_addr) {
        out->load_bias_guest = out->guest_addr - analysis_addr;
    } else if (out->map_start_guest) {
        out->load_bias_guest = out->map_start_guest - seg_vaddr_at_map_start;
    }

    out->module_name = module->name;
    out->module_real_path = module->real_path;

    func = module_find_func(module, analysis_addr);
    if (func) {
        out->func_name = func->name;
        out->func_prototype = func->prototype;
        out->func_entry = func->entry;
        out->func_size = func->size;
        out->func_offset = analysis_addr - func->entry;
        out->pseudocode_file = func->pseudocode_file;
        out->pseudocode = read_file_prefix(func->pseudocode_file, max_pseudocode_bytes,
                                           &out->pseudocode_truncated);
    }

    g_free((char *)map->path);
    g_free(map);
    g_mutex_unlock(&sfdb_lock);
    return 0;
}
