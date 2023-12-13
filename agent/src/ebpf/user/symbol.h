/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _BPF_SYMBOL_H_
#define _BPF_SYMBOL_H_
#include <stdint.h>
#include "types.h"
#include "clib.h"
#include "mem.h"
#include "vec.h"
#include "bihash_8_16.h"
#include "list.h"

/*
 * symbol_caches_hash_t maps from pid to BCC symbol cache.
 */

#define symbol_caches_hash_t        clib_bihash_8_16_t
#define symbol_caches_hash_init     clib_bihash_init_8_16
#define symbol_caches_hash_kv       clib_bihash_kv_8_16_t
#define print_hash_symbol_caches    print_bihash_8_16
#define symbol_caches_hash_search   clib_bihash_search_8_16
#define symbol_caches_hash_add_del  clib_bihash_add_del_8_16
#define symbol_caches_hash_free     clib_bihash_free_8_16
#define symbol_caches_hash_key_value_pair_cb        clib_bihash_foreach_key_value_pair_cb_8_16
#define symbol_caches_hash_foreach_key_value_pair   clib_bihash_foreach_key_value_pair_8_16

#define FUNC_RET_MAX 32

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct symbol_cache_del_pids {
	struct symbolizer_cache_kvp *pid_caches;
	volatile u32 *lock;
};

struct symbolizer_proc_info {
	int pid;
	/* The process creation time since
	 * system boot, (in milliseconds) */
	u64 stime;
	u64 netns_id;
	/*
	 * Sometimes the process name set by some processes will be delayed.
	 * When the process is just started, the name may change later. This
	 * is used to delay confirmation.
	 */
	bool verified;
	/* To mark whether it is a Java process? */
	bool is_java;
	/* Determine if the Java symbol file generation has been added to tasks list. */
	bool add_task_list;
	/* Have a new perf map file ? */
	bool new_java_syms_file;
	/* Java symbol cache needs updating? */
	bool cache_need_update;
	/* Did the generation of the Java symbol file encounter any exceptions? */
	bool gen_java_syms_file_err;
	/* Unknown symbols was found, and it is currently mainly used to
	 * obtain the match of the Java process.*/
	bool unknown_syms_found;
	/* Expiration time (in seconds) for updating the Java symbol table */
	u64 update_syms_table_time;
	/* process name */
	char comm[TASK_COMM_LEN];
	/* container id */
	char container_id[CONTAINER_ID_SIZE];
	/* reference counting */
	u64 use;
};

struct symbolizer_cache_kvp {
	struct {
		u64 pid;
	} k;

	struct {
		/* struct symbolizer_proc_info address */
		uword proc_info_p;
		/* memoized bcc symbol caches */
		uword cache;
	} v;
};

struct tracer_probes_conf;

enum uprobe_type {
	GO_UPROBE = 0,
	OPENSSL_UPROBE,
	OTHER_UPROBE
};

enum proc_act_type {
	PROC_EXEC = 0,
	PROC_EXIT
};

struct symbol {
	enum uprobe_type type;
	const char *symbol;
	const char *probe_func;
	bool is_probe_ret;
};

struct version_info {
	int major;
	int minor;
	int revision;
};

struct load_addr_t {
	uint64_t target_addr;
	uint64_t binary_addr;
};

struct symbol_uprobe {
	struct list_head list;
	enum uprobe_type type;
	int pid;
	unsigned long long starttime;	// process start time.
	const char *name;	//symbol名字
	const char *binary_path;	//so或目标可执行文件全路径
	const char *probe_func;
	size_t entry;		//入口地址
	uint64_t size;		//函数块大小
	struct version_info ver;
	size_t rets[FUNC_RET_MAX];
	int rets_count;		// 返回数量 可用来判断是否attch rets
	bool isret;
	bool in_probe;		// already in probe, if or not ?
};

struct symbol_kprobe {
	bool isret;		// only use kprobe
	char *symbol;		// only use uprobe
	char *func;
};

struct symbol_tracepoint {
	char *name;
};

static_always_inline u64
cache_process_stime(struct symbolizer_cache_kvp *kv)
{
	return (u64)((struct symbolizer_proc_info *)kv->v.proc_info_p)->stime;
}

static_always_inline u64
cache_process_netns_id(struct symbolizer_cache_kvp *kv)
{
	return (u64)((struct symbolizer_proc_info *)kv->v.proc_info_p)->netns_id;
}

static_always_inline void
copy_process_name(struct symbolizer_cache_kvp *kv, char *dst)
{
	static const int len =
		sizeof(((struct symbolizer_proc_info *)kv->v.proc_info_p)->comm);

	strcpy_s_inline(dst, len,
			((struct symbolizer_proc_info *)kv->v.proc_info_p)->comm,
			strlen(((struct symbolizer_proc_info *)kv->v.proc_info_p)->comm));
}

void free_uprobe_symbol(struct symbol_uprobe *u_sym,
			struct tracer_probes_conf *conf);
void add_uprobe_symbol(int pid, struct symbol_uprobe *u_sym,
		       struct tracer_probes_conf *conf);
int copy_uprobe_symbol(struct symbol_uprobe *src, struct symbol_uprobe *dst);
char *get_elf_path_by_pid(int pid);
struct symbol_uprobe *resolve_and_gen_uprobe_symbol(const char *bin_file,
						    struct symbol *sym,
						    const uint64_t addr,
						    int pid);
uint64_t get_symbol_addr_from_binary(const char *bin, const char *symname);
void get_process_info_by_pid(pid_t pid, u64 * stime, u64 * netns_id, char *name,
			     void **ptr);
#ifndef AARCH64_MUSL
void *get_symbol_cache(pid_t pid, bool new_cache);
void release_symbol_caches(void);
u64 get_pid_stime(pid_t pid);
void exec_proc_info_cache_update(void);
void set_java_syms_fetch_delay(int delay_secs);
u64 get_java_syms_fetch_delay(void);
#endif
int create_and_init_proc_info_caches(void);
void get_container_id_from_procs_cache(pid_t pid, uint8_t * id, int id_size);
void update_proc_info_cache(pid_t pid, enum proc_act_type type);
#endif /* _BPF_SYMBOL_H_ */
