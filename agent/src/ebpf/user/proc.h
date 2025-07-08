/*
 * Copyright (c) 2024 Yunshan Networks
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

#ifndef _USER_PROC_H_
#define _USER_PROC_H_
#include <stdint.h>
#include "types.h"
#include "clib.h"
#include "mem.h"
#include "vec.h"
#include "bihash_8_8.h"
#include "list.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/*
 * symbol_caches_hash_t maps from pid to BCC symbol cache.
 */

#define symbol_caches_hash_t        clib_bihash_8_8_t
#define symbol_caches_hash_init     clib_bihash_init_8_8
#define symbol_caches_hash_kv       clib_bihash_kv_8_8_t
#define print_hash_symbol_caches    print_bihash_8_8
#define symbol_caches_hash_search   clib_bihash_search_8_8
#define symbol_caches_hash_add_del  clib_bihash_add_del_8_8
#define symbol_caches_hash_free     clib_bihash_free_8_8
#define symbol_caches_hash_key_value_pair_cb        clib_bihash_foreach_key_value_pair_cb_8_8
#define symbol_caches_hash_foreach_key_value_pair   clib_bihash_foreach_key_value_pair_8_8
typedef u32 kern_dev_t;
#define DEV_INVALID ((kern_dev_t)-1)
struct mount_entry {
	struct list_head list;              // Linked list node for chaining multiple mount entries
	kern_dev_t s_dev;                   // Device ID (major:minor) where the mount resides
	bool is_nfs;                        // True if the mount source is an NFS (Network File System)
	char mount_point[MAX_PATH_LENGTH];  // Path where the filesystem is mounted (e.g., "/mnt/data")
	char mount_source[MAX_PATH_LENGTH]; // Source of the mount (e.g., "/dev/sda1" or "server:/export")
};

struct symbol_cache_pids {
	struct symbolizer_cache_kvp *exec_pids_cache;
	struct symbolizer_cache_kvp *exit_pids_cache;
	volatile u32 *lock;
};

/*
 * The information used to record the names of threads or processes obtained in
 * the process currently mainly includes the name and its corresponding index
 * value. It is used for statistical aggregation in tracking stack strings.
 */
struct task_comm_info_s {
	int idx;
	/* Add a prefix here: 'P' for processes and 'T' for threads. */
	char comm[TASK_COMM_LEN + 1];
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
	/* Is it necessary to create a new Java symbol collector? */
	bool need_new_symbol_collector;
	/* Expiration time (in seconds) for updating the Java symbol table */
	u64 update_syms_table_time;
	/* process name */
	char comm[TASK_COMM_LEN];
	/* Thread names vector */
	struct task_comm_info_s *thread_names;
	u32 thread_names_lock;
	/* container id */
	char container_id[CONTAINER_ID_SIZE];
	/* reference counting */
	u64 use;
	/* Has the process exited? */
	u64 is_exit;
	/* Protect symbolizer_proc_info from concurrent access by multiple threads. */
	u32 lock;
	/* Multithreaded symbol resolution protection. */
	pthread_mutex_t mutex;
	/* Recording symbol resolution cache. */
	volatile uword syms_cache;
	/* Mount information of the process */
	struct list_head mount_head;
};

static inline void thread_names_lock(struct symbolizer_proc_info *p)
{
	while (__atomic_test_and_set(&p->thread_names_lock, __ATOMIC_ACQUIRE))
		CLIB_PAUSE();
}

static inline void thread_names_unlock(struct symbolizer_proc_info *p)
{
	__atomic_clear(&p->thread_names_lock, __ATOMIC_RELEASE);
}

static inline void symbolizer_proc_lock(struct symbolizer_proc_info *p)
{
	while (__atomic_test_and_set(&p->lock, __ATOMIC_ACQUIRE))
		CLIB_PAUSE();
}

static inline void symbolizer_proc_unlock(struct symbolizer_proc_info *p)
{
	__atomic_clear(&p->lock, __ATOMIC_RELEASE);
}

struct symbolizer_cache_kvp {
	struct {
		u64 pid;
	} k;

	struct {
		/* struct symbolizer_proc_info address */
		uword proc_info_p;
	} v;
};

static_always_inline u64 cache_process_stime(struct symbolizer_cache_kvp *kv)
{
	struct symbolizer_proc_info *p =
	    (struct symbolizer_proc_info *)kv->v.proc_info_p;
	u64 stime;
	AO_INC(&p->use);
	stime = p->stime;
	AO_DEC(&p->use);
	return stime;
}

static_always_inline u64 cache_process_netns_id(struct symbolizer_cache_kvp *
						kv)
{
	struct symbolizer_proc_info *p =
	    (struct symbolizer_proc_info *)kv->v.proc_info_p;
	u64 netns_id;
	AO_INC(&p->use);
	netns_id = p->netns_id;
	AO_DEC(&p->use);
	return netns_id;
}

static_always_inline void
copy_process_name(struct symbolizer_cache_kvp *kv, char *dst)
{
	struct symbolizer_proc_info *p =
	    (struct symbolizer_proc_info *)kv->v.proc_info_p;
	AO_INC(&p->use);
	static const int len = sizeof(p->comm);
	strcpy_s_inline(dst, len, p->comm, len);
	AO_DEC(&p->use);
}

void get_process_info_by_pid(pid_t pid, u64 * stime, u64 * netns_id, char *name,
			     void **ptr);
u64 get_proc_exec_event_count(void);
u64 get_proc_exit_event_count(void);
void clear_proc_exec_event_count(void);
void clear_proc_exit_event_count(void);
#ifndef AARCH64_MUSL
int creat_ksyms_cache(void);
void *get_symbol_cache(pid_t pid, bool new_cache);
void release_symbol_caches(void);
u64 get_pid_stime(pid_t pid);
void set_java_syms_fetch_delay(int delay_secs);
u64 get_java_syms_fetch_delay(void);
void free_proc_cache(struct symbolizer_proc_info *p);
void symbolizer_kernel_lock(void);
void symbolizer_kernel_unlock(void);
#endif
void exec_proc_info_cache_update(void);
int create_and_init_proc_info_caches(void);
/**
 * @brief Retrieve container ID, process name, and mount point from the cache based on a PID.
 *
 * This function looks up the given PID in the symbolizer/process cache to retrieve:
 *   - the associated container ID (`cid`),
 *   - the process name (`name`, i.e., comm),
 *   - and optionally the mount point corresponding to a given `s_dev` value.
 *
 * If the process is not found in the cache, all output buffers (`cid`, `name`, `mount_point`)
 * will be zeroed.
 *
 * @param pid          The process ID to look up.
 * @param cid          Output buffer to store the container ID.
 * @param cid_size     Size of the `cid` buffer in bytes.
 * @param name         Output buffer to store the process name (comm).
 * @param name_size    Size of the `name` buffer in bytes.
 * @param s_dev        Device number to be resolved into a mount point path.
 * @param mount_point  Output buffer to store the mount point path matching `s_dev`.
 * @param mount_source Output buffer to store the mount source path.
 * @param mount_size   Size of the `mount_point` buffer in bytes.
 * @param is_nfs       Is it an NFS file system?
 *
 * @return
 *    0 : Successfully found process info in cache and retrieved data.
 *   -1 : Process not found in cache; output buffers may be zero-filled or unchanged.
 *
 * @note If the process entry is found, its reference count is safely managed
 *       (incremented before use and decremented after).
 * @note If no valid data is found, `cid`, `name`, and `mount_point` will be
 *       zeroed.
 */
int get_proc_info_from_cache(pid_t pid, uint8_t *cid, int cid_size,
			     uint8_t *name, int name_size, kern_dev_t s_dev,
			     char *mount_point, char *mount_source,
			     int mount_size, bool *is_nfs);
void update_proc_info_cache(pid_t pid, enum proc_act_type type);

// Lower version kernels do not support hooking so files in containers
bool kernel_version_check(void);
bool process_probing_check(int pid);

struct process_create_event {
	struct list_head list;
	int pid;
	uint64_t stime; // Process start time
	uint32_t expire_time;
	char *path;
	struct bpf_tracer *tracer;
};

typedef struct {
	struct list_head head;
	pthread_mutex_t m;
} proc_event_list_t;

void add_event_to_proc_list(proc_event_list_t * list, struct bpf_tracer *tracer,
			    int pid, char *path);
void process_event_free(struct process_create_event *event);
void remove_event(proc_event_list_t * list, struct process_create_event *event);
struct process_create_event *get_first_event(proc_event_list_t * list);

bool check_so_path_by_pid_and_name(int pid, const char *so_name);
char *get_so_path_by_pid_and_name(int pid, const char *so_name);
int add_probe_sym_to_tracer_probes(int pid, const char *path,
				   struct tracer_probes_conf *conf,
				   struct symbol symbols[], size_t n_symbols);
/**
 * @brief Build a mount cache for the specified process ID.
 *
 * This function reads `/proc/<pid>/mountinfo`, parses each mount entry,
 * and appends (s_dev, mount_point) pairs into a linked list provided by
 * the caller via `mount_head`.
 *
 * Each node in the list should typically contain:
 *   - The device number (`kern_dev_t`)
 *   - The mount point path
 *
 * The list must be initialized before calling this function.
 *
 * @param pid         The PID of the process whose mount info is to be parsed.
 * @param mount_head  Pointer to the head of a linked list that will hold
 *                    parsed mount entries (s_dev and mount path).
 *
 * @return 0 on success, -1 on failure (e.g., file open error or parsing issue).
 */
int build_mount_cache_for_pid(pid_t pid, struct list_head *mount_head);

/**
 * @brief Free the mount information list for a process.
 *
 * This function frees all nodes in the linked list `mount_head`, which
 * should contain elements of type `struct mount_entry`. Each node is removed
 * from the list and its memory is released.
 *
 * It is typically used to clean up the mount information parsed from
 * `/proc/<pid>/mountinfo` and stored using a function like
 * `build_mount_cache_for_pid()`.
 *
 * @param mount_head Pointer to the head of the mount entry list to be freed.
 */
void proc_mount_info_free(struct list_head *mount_head);

/**
 * @brief Find the mount point path corresponding to a given device ID.
 *
 * This function iterates over a list of parsed mount entries and looks
 * for the first entry whose `s_dev` matches the specified device ID.
 * If found, it copies the corresponding mount point path into the provided buffer.
 *
 * @param mount_head   Pointer to the head of the mount entry list (linked list of mount_entry).
 * @param s_dev        Device ID (kern_dev_t) to match against entries in the list.
 * @param mount_point  Output buffer to receive the matching mount point path.
 * @param mount_source Output buffer to receive the matching mount source path.
 * @param mount_size   Size of the output buffer `mount_path`.
 * @param is_nfs       Whether it is an NFS file system.
 *
 * @note If multiple entries match the same `s_dev`, the last one found will overwrite previous ones.
 *       If no match is found, `mount_path` will remain unchanged.
 */
void find_mount_point_path(struct list_head *mount_head, kern_dev_t s_dev,
			   char *mount_path, char *mount_source,
			   int mount_size, bool *is_nfs);
#endif /* _USER_PROC_H_ */
