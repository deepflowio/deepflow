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

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <gelf.h>
#include <libelf.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>		//PATH_MAX(4096)
#include <bcc/bcc_proc.h>
#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <dirent.h>		// for opendir()
#include "config.h"
#include "elf.h"
#include "log.h"
#include "common.h"
#include "symbol.h"
#include "proc.h"
#include "tracer.h"
#include "load.h"
#if defined __x86_64__
#include "bddisasm/bddisasm.h"
#include "bddisasm/disasmtypes.h"
#endif
#include "libGoReSym.h"
#include "profile/perf_profiler.h"
#include "profile/java/df_jattach.h"
#include "profile/java/gen_syms_file.h"
#include "bihash_8_8.h"
#include "profile/stringifier.h"
#include "profile/profile_common.h"

static u64 add_symcache_count;
static u64 free_symcache_count;

// Process exec/exit event information
struct proc_event_info {
	enum proc_act_type type;
	struct symbolizer_cache_kvp kv;
};

static u64 proc_exec_event_count;
static u64 proc_exit_event_count;

/**
 * @brief Use multi-producer, single-consumer queue to handle process
 * execution and exit events.
 *
 * Producer:
 *   The 'sk-reader' thread (handled in the 'process_event()' interface) is
 *   used to receive process events captured by eBPF.
 * Consumer:
 *   The 'proc-events' is used to handle process events (handled in the
 *   'exec_proc_info_cache_update()' interface). 
 */
static struct ring *proc_event_ring;

/*
 * To allow Java to run for an extended period and gather more symbol
 * information, we delay symbol retrieval when encountering unknown symbols.
 * The default value is 'JAVA_SYMS_UPDATE_DELAY_DEF'.
 */
static volatile u64 java_syms_fetch_delay;	// In seconds.

/*
 * When a process exits, save the symbol cache pids
 * to be deleted.
 */
static struct symbol_cache_pids pids_cache;

static struct bcc_symbol_option lazy_opt = {
	.use_debug_file = false,
	.check_debug_file_crc = false,
	.lazy_symbolize = true,
	.use_symbol_type = ((1 << STT_FUNC) | (1 << STT_GNU_IFUNC)),
};

static int config_symbolizer_proc_info(struct symbolizer_proc_info *p, int pid);

u64 get_proc_exec_event_count(void)
{
	return proc_exec_event_count;
}

u64 get_proc_exit_event_count(void)
{
	return proc_exit_event_count;
}

void set_java_syms_fetch_delay(int delay_secs)
{
	java_syms_fetch_delay = delay_secs;
}

u64 get_java_syms_fetch_delay(void)
{
	return java_syms_fetch_delay;
}

#ifndef AARCH64_MUSL
/**
 * @brief Symbol table caches of process information.
 * 
 * You can obtain process information using the process PID.
 */
symbol_caches_hash_t syms_cache_hash;
static void *k_resolver;	// for kernel symbol cache
static volatile u32 k_resolver_lock;
static u64 sys_btime_msecs;	// system boot time(milliseconds)

void symbolizer_kernel_lock(void)
{
	while (__atomic_test_and_set(&k_resolver_lock, __ATOMIC_ACQUIRE))
		CLIB_PAUSE();
}

void symbolizer_kernel_unlock(void)
{
	__atomic_clear(&k_resolver_lock, __ATOMIC_RELEASE);
}

static bool inline enable_proc_info_cache(void)
{
	return (syms_cache_hash.buckets != NULL);
}

void free_proc_cache(struct symbolizer_proc_info *p)
{
	if (p->is_java) {
		/* Delete target ns Java files */
		int pid = (int)p->pid;
		if (pid > 0) {
			clean_local_java_symbols_files(pid);
		}
	}

	if (p->syms_cache) {
		bcc_free_symcache((void *)p->syms_cache, p->pid);
		free_symcache_count++;
	}
	p->syms_cache = 0;
	clib_mem_free((void *)p);
}

static void free_symbolizer_cache_kvp(struct symbolizer_cache_kvp *kv)
{
	if (kv->v.proc_info_p) {
		struct symbolizer_proc_info *p;
		p = (struct symbolizer_proc_info *)kv->v.proc_info_p;
		AO_DEC(&p->use);
		/* Ensure that all tasks are completed before releasing. */
		while (AO_GET(&p->use) != 0)
			CLIB_PAUSE();
		free_proc_cache(p);
		kv->v.proc_info_p = 0;
	}
}

static inline void symbol_cache_pids_lock(void)
{
	while (__atomic_test_and_set(pids_cache.lock, __ATOMIC_ACQUIRE))
		CLIB_PAUSE();
}

static inline void symbol_cache_pids_unlock(void)
{
	__atomic_clear(pids_cache.lock, __ATOMIC_RELEASE);
}

static inline bool is_existed_in_exit_cache(struct symbolizer_cache_kvp *kv)
{
	/*
	 * Make sure that there are no duplicate items of 'pid' in
	 * 'cache del pids.pid caches', so as to avoid program crashes
	 * caused by repeated release of occupied memory resources.
	 */
	struct symbolizer_cache_kvp *kv_tmp;
	vec_foreach(kv_tmp, pids_cache.exit_pids_cache) {
		if ((int)kv_tmp->k.pid == kv->k.pid) {
			struct symbolizer_proc_info *list_p =
			    (struct symbolizer_proc_info *)kv_tmp->v.
			    proc_info_p;
			struct symbolizer_proc_info *curr_p =
			    (struct symbolizer_proc_info *)kv->v.proc_info_p;
			ebpf_warning
			    (" At list pid %lu kvp_pid %lu info_p 0x%lx (p->cache 0x%lx)"
			     " curr: pid %lu kvp_pid %lu info_p 0x%lx (p->cache 0x%lx)\n",
			     (u64) list_p->pid, kv_tmp->k.pid,
			     kv_tmp->v.proc_info_p,
			     kv_tmp->v.proc_info_p !=
			     0 ? list_p->syms_cache : 0, (u64) curr_p->pid,
			     kv->k.pid, kv->v.proc_info_p,
			     kv->v.proc_info_p != 0 ? curr_p->syms_cache : 0);
			return true;
		}
	}

	return false;
}

static inline bool is_existed_in_exec_cache(struct symbolizer_cache_kvp *kv)
{
	/*
	 * Make sure that there are no duplicate items of 'pid' in
	 * 'cache del pids.pid caches', so as to avoid program crashes
	 * caused by repeated release of occupied memory resources.
	 */
	struct symbolizer_cache_kvp *kv_tmp;
	vec_foreach(kv_tmp, pids_cache.exec_pids_cache) {
		if ((int)kv_tmp->k.pid == kv->k.pid) {
			struct symbolizer_proc_info *list_p =
			    (struct symbolizer_proc_info *)kv_tmp->v.
			    proc_info_p;
			struct symbolizer_proc_info *curr_p =
			    (struct symbolizer_proc_info *)kv->v.proc_info_p;
			if (curr_p != 0 && list_p != 0) {
				ebpf_warning
				    (" At list pid %lu kvp_pid %lu info_p 0x%lx (p->cache 0x%lx)"
				     " curr: pid %lu kvp_pid %lu info_p 0x%lx (p->cache 0x%lx)\n",
				     (u64) list_p->pid, kv_tmp->k.pid,
				     kv_tmp->v.proc_info_p,
				     kv_tmp->v.proc_info_p !=
				     0 ? list_p->syms_cache : 0,
				     (u64) curr_p->pid, kv->k.pid,
				     kv->v.proc_info_p,
				     kv->v.proc_info_p !=
				     0 ? curr_p->syms_cache : 0);
			}
			return true;
		}
	}

	return false;
}

static inline struct symbolizer_proc_info *add_proc_info_to_cache(struct
								  symbolizer_cache_kvp
								  *kv)
{
	pid_t pid = (pid_t) kv->k.pid;
	symbol_caches_hash_t *h = &syms_cache_hash;
	struct symbolizer_proc_info *p = NULL;
	p = clib_mem_alloc_aligned("sym_proc_info",
				   sizeof(struct
					  symbolizer_proc_info), 0, NULL);
	if (p == NULL) {
		/* exit process */
		ebpf_warning("Failed to build process information table.\n");
		return NULL;
	}

	if (config_symbolizer_proc_info(p, pid) != ETR_OK) {
		clib_mem_free(p);
		return NULL;
	}

	kv->v.proc_info_p = pointer_to_uword(p);
	int ret;
	if ((ret = symbol_caches_hash_add_del
	     (h, (symbol_caches_hash_kv *) kv,
	      2 /* is_add = 2, Add but do not overwrite? */ )) != 0) {
		// If it already exists, return -2.
		if (ret != -2)
			ebpf_warning
			    ("symbol_caches_hash_add_del() failed.(pid %d), return %d\n",
			     pid, ret);
		free_symbolizer_cache_kvp(kv);
		return NULL;
	} else {
		/* Extended handling associated with process execute event. */
		extended_proc_event_handler(pid, p->comm, PROC_EXEC);
		__sync_fetch_and_add(&h->hash_elems_count, 1);
	}

	return p;
}

static inline int del_proc_info_from_cache(struct symbolizer_cache_kvp *kv)
{
	if (kv->v.proc_info_p) {
		struct symbolizer_proc_info *p;
		p = (struct symbolizer_proc_info *)kv->v.proc_info_p;
		/* Extended handling associated with process exit event. */
		extended_proc_event_handler((int)kv->k.pid, p->comm, PROC_EXIT);
	}

	free_symbolizer_cache_kvp(kv);
	return 0;
}

void get_container_id_from_procs_cache(pid_t pid, uint8_t * id, int id_size)
{
	symbol_caches_hash_t *h = &syms_cache_hash;
	struct symbolizer_cache_kvp kv;
	kv.k.pid = (u64) pid;
	kv.v.proc_info_p = 0;
	memset(id, 0, id_size);
	struct symbolizer_proc_info *p = NULL;
	if (symbol_caches_hash_search(h, (symbol_caches_hash_kv *) & kv,
				      (symbol_caches_hash_kv *) & kv) == 0) {
		p = (struct symbolizer_proc_info *)kv.v.proc_info_p;
		AO_INC(&p->use);
		if (strlen(p->container_id) > 0) {
			memcpy_s_inline((void *)id, id_size, p->container_id,
					sizeof(p->container_id));
		}
		AO_DEC(&p->use);
		return;
	}

	fetch_container_id(pid, (char *)id, id_size);
}

static inline int add_proc_ev_info_to_ring(enum proc_act_type type,
					   struct symbolizer_cache_kvp *kv)
{
	if (proc_event_ring == NULL)
		return -1;

	struct proc_event_info *ev_info;
	ev_info = clib_mem_alloc_aligned("proc-cache-kvp",
					 sizeof(*ev_info), 0, NULL);
	ev_info->type = type;
	ev_info->kv = *kv;
	int nr = ring_mp_enqueue_burst(proc_event_ring, (void **)&ev_info, 1,
				       NULL);
	if (nr < 1) {
		clib_mem_free(ev_info);
		ebpf_info("Failed to add process %d to the queue, so it "
			  "was added to the vector instead.\n", kv->k.pid);
		return -1;
	}

	return 0;
}

/*
 * When a process exits, synchronize and update its corresponding
 * symbol cache. In addition, updating the Java process symbol t-
 * able also requires calling this interface.
 *
 * @pid : The process ID (PID) that occurs when a process exits.
 * @type : process event type
 */
void update_proc_info_cache(pid_t pid, enum proc_act_type type)
{
	if (!enable_proc_info_cache()) {
		return;
	}

	symbol_caches_hash_t *h = &syms_cache_hash;
	struct symbolizer_cache_kvp kv = {};
	kv.k.pid = (u64) pid;
	kv.v.proc_info_p = 0;

	if (type == PROC_EXEC) {
		__sync_fetch_and_add(&proc_exec_event_count, 1);

		/* To filter out threads. */
		if (!is_user_process(pid)) {
			return;
		}

		if (add_proc_ev_info_to_ring(type, &kv) < 0) {
			int ret = VEC_OK;
			symbol_cache_pids_lock();
			if (is_existed_in_exec_cache(&kv)) {
				symbol_cache_pids_unlock();
				return;
			}

			vec_add1(pids_cache.exec_pids_cache, kv, ret);
			if (ret != VEC_OK) {
				ebpf_warning("vec add failed.\n");
			}
			symbol_cache_pids_unlock();
		}
	} else
		__sync_fetch_and_add(&proc_exit_event_count, 1);

	if (symbol_caches_hash_search(h, (symbol_caches_hash_kv *) & kv,
				      (symbol_caches_hash_kv *) & kv) == 0) {
		int ret = VEC_OK;
		struct symbolizer_proc_info *p;
		p = (struct symbolizer_proc_info *)kv.v.proc_info_p;
		if (p != NULL) {
			AO_INC(&p->use);
			p->is_exit = 1;
			AO_DEC(&p->use);
			CLIB_MEMORY_STORE_BARRIER();
		}
		if (add_proc_ev_info_to_ring(type, &kv) < 0) {
			symbol_cache_pids_lock();
			if (is_existed_in_exit_cache(&kv)) {
				symbol_cache_pids_unlock();
				return;
			}

			vec_add1(pids_cache.exit_pids_cache, kv, ret);
			if (ret != VEC_OK) {
				ebpf_warning("vec add failed.\n");
			}
			symbol_cache_pids_unlock();
		}

		if (symbol_caches_hash_add_del
		    (h, (symbol_caches_hash_kv *) & kv, 0 /* delete */ )) {
			ebpf_warning("failed.(pid %d)\n", (pid_t) kv.k.pid);
			return;
		} else {
			__sync_fetch_and_add(&h->hash_elems_count, -1);
		}
	}
}

void exec_proc_info_cache_update(void)
{
	struct symbolizer_cache_kvp *kv;
	if (proc_event_ring == NULL)
		goto vector_handle;
	int nr;
	void *rx_burst[MAX_PKT_BURST];
	do {
		nr = ring_sc_dequeue_burst(proc_event_ring, rx_burst,
					   MAX_PKT_BURST, NULL);
		int i;
		struct proc_event_info *ev_info;
		for (i = 0; i < nr; i++) {
			ev_info = rx_burst[i];
			if (ev_info->type == PROC_EXEC) {
				add_proc_info_to_cache(&ev_info->kv);
			} else {
				del_proc_info_from_cache(&ev_info->kv);
			}
			clib_mem_free(ev_info);
		}
	} while (nr > 0);

vector_handle:
	symbol_cache_pids_lock();
	vec_foreach(kv, pids_cache.exit_pids_cache) {
		del_proc_info_from_cache(kv);
	}
	vec_free(pids_cache.exit_pids_cache);

	vec_foreach(kv, pids_cache.exec_pids_cache) {
		add_proc_info_to_cache(kv);
	}
	vec_free(pids_cache.exec_pids_cache);

	symbol_cache_pids_unlock();
}

static int init_symbol_cache(const char *name)
{
	/*
	 * Thread-safe for pids_cache.pids
	 */
	pids_cache.lock =
	    clib_mem_alloc_aligned("pids_alloc_lock",
				   CLIB_CACHE_LINE_BYTES,
				   CLIB_CACHE_LINE_BYTES, NULL);
	if (pids_cache.lock == NULL) {
		ebpf_error("pids_cache.lock alloc memory failed.\n");
		return (-1);
	}

	pids_cache.lock[0] = 0;
	pids_cache.exit_pids_cache = NULL;
	pids_cache.exec_pids_cache = NULL;

	symbol_caches_hash_t *h = &syms_cache_hash;
	memset(h, 0, sizeof(*h));
	u32 nbuckets = SYMBOLIZER_CACHES_HASH_BUCKETS_NUM;
	u64 hash_memory_size = SYMBOLIZER_CACHES_HASH_MEM_SZ;	// 2G bytes
	return symbol_caches_hash_init(h, (char *)name, nbuckets,
				       hash_memory_size);
}

u64 get_pid_stime(pid_t pid)
{
	ASSERT(pid >= 0);

	symbol_caches_hash_t *h = &syms_cache_hash;
	struct symbolizer_cache_kvp kv;

	if (pid == 0)
		return sys_btime_msecs;

	kv.k.pid = (u64) pid;
	kv.v.proc_info_p = 0;
	if (symbol_caches_hash_search(h, (symbol_caches_hash_kv *) & kv,
				      (symbol_caches_hash_kv *) & kv) == 0) {
		return cache_process_stime(&kv);
	}

	return 0;
}

static int config_symbolizer_proc_info(struct symbolizer_proc_info *p, int pid)
{
	memset(p, 0, sizeof(*p));
	p->pid = pid;
	p->add_task_list = false;
	p->unknown_syms_found = false;
	p->new_java_syms_file = false;
	p->cache_need_update = false;
	p->gen_java_syms_file_err = false;
	p->lock = 0;
	pthread_mutex_init(&p->mutex, NULL);
	p->syms_cache = 0;
	p->netns_id = get_netns_id_from_pid(pid);
	if (p->netns_id == 0)
		return ETR_INVAL;

	fetch_container_id(pid, p->container_id, sizeof(p->container_id));

	p->stime = (u64) get_process_starttime_and_comm(pid,
							p->comm,
							sizeof(p->comm));
	p->comm[sizeof(p->comm) - 1] = '\0';
	if (p->stime == 0)
		return ETR_INVAL;

	if (strcmp(p->comm, "java") == 0)
		p->is_java = true;
	else
		p->is_java = false;

	if ((current_sys_time_secs() - (p->stime / 1000ULL)) >=
	    PROC_INFO_VERIFY_TIME) {
		p->verified = true;
	} else {
		p->verified = false;
	}

	p->use = 1;

	return ETR_OK;
}

static inline void write_return_value(struct symbolizer_cache_kvp *kv,
				      struct symbolizer_proc_info *p,
				      u64 * stime, u64 * netns_id, char *name,
				      void **ptr)
{
	copy_process_name(kv, name);
	*stime = cache_process_stime(kv);
	*netns_id = cache_process_netns_id(kv);
	*ptr = p;
}

void get_process_info_by_pid(pid_t pid, u64 * stime, u64 * netns_id, char *name,
			     void **ptr)
{
	ASSERT(pid >= 0 && stime != NULL && netns_id != NULL && name != NULL);

	*stime = *netns_id = 0;
	*ptr = NULL;
	symbol_caches_hash_t *h = &syms_cache_hash;
	struct symbolizer_cache_kvp kv;

	if (pid == 0) {
		*stime = sys_btime_msecs;
		return;
	}

	kv.k.pid = (u64) pid;
	kv.v.proc_info_p = 0;
	struct symbolizer_proc_info *p = NULL;
	if (symbol_caches_hash_search(h, (symbol_caches_hash_kv *) & kv,
				      (symbol_caches_hash_kv *) & kv) != 0) {
		return;
	} else {
		p = (struct symbolizer_proc_info *)kv.v.proc_info_p;
		AO_INC(&p->use);
		symbolizer_proc_lock(p);
		u64 curr_time = current_sys_time_secs();
		if (!p->verified) {
			if (((curr_time - (p->stime / 1000ULL)) <
			     PROC_INFO_VERIFY_TIME)) {
				write_return_value(&kv, p, stime, netns_id,
						   name, ptr);
				symbolizer_proc_unlock(p);
				return;
			}

			/*
			 * To prevent the possibility of the process name being changed
			 * shortly after the program's initial startup, as a precaution,
			 * we will reacquire it after the program has been running stably
			 * for a period of time to avoid such situations.
			 */
			char comm[sizeof(p->comm)];
			u64 proc_stime = (u64)
			    get_process_starttime_and_comm(pid,
							   comm,
							   sizeof(comm));
			if (proc_stime == 0) {
				/* 
				 * Here, indicate that during the symbolization process,
				 * the process has already terminated, but the process
				 * information has not yet been cleared. In this case, we
				 * continue to use the previously retained information.
				 */
				write_return_value(&kv, p, stime, netns_id,
						   name, ptr);
				symbolizer_proc_unlock(p);
				return;
			}

			p->stime = proc_stime;
			memcpy(p->comm, comm, sizeof(p->comm));
			p->comm[sizeof(p->comm) - 1] = '\0';

			if (strcmp(p->comm, "java") == 0)
				p->is_java = true;
			else
				p->is_java = false;

			p->verified = true;
		}

		write_return_value(&kv, p, stime, netns_id, name, ptr);
		symbolizer_proc_unlock(p);
	}
}

static void *symbols_cache_update(symbol_caches_hash_t * h,
				  struct symbolizer_cache_kvp *kv,
				  struct symbolizer_proc_info *p)
{
	if (p->is_java && !p->cache_need_update)
		goto exit;

	if (p->syms_cache)
		bcc_free_symcache((void *)p->syms_cache, kv->k.pid);

	p->syms_cache =
	    pointer_to_uword(bcc_symcache_new((int)kv->k.pid, &lazy_opt));

	if (p->syms_cache <= 0) {
		p->syms_cache = 0;
		goto exit;
	}

	ebpf_info("cache update PID %d NAME %s\n", kv->k.pid, p->comm);
	add_symcache_count++;

exit:
	p->unknown_syms_found = false;
	p->update_syms_table_time = 0;
	p->new_java_syms_file = false;
	p->add_task_list = false;
	p->cache_need_update = false;
	CLIB_MEMORY_STORE_BARRIER();

	return (void *)p->syms_cache;
}

static inline void java_expired_update(symbol_caches_hash_t * h,
				       struct symbolizer_cache_kvp *kv,
				       struct symbolizer_proc_info *p)
{
	ASSERT(p != NULL);

	/* Update java symbols table, will be executed during
	 * the next Java symbolication */

	/* Has the symbol file for Java been generated ? */
	if (AO_GET(&p->new_java_syms_file)) {
		symbols_cache_update(h, kv, p);
	} else {
		if (!p->add_task_list) {
			add_java_syms_update_task(p);
			p->add_task_list = true;
		}
	}
}

/*
 * Cache for obtaining symbol information of the binary
 * executable corresponding to a PID, and rebuilding it
 * if the cache does not exist.
 *
 * Only used for parsing stack trace data in kernel space
 * and user space. If it is a kernel space stack trace
 * (k_stack_trace_id), the PID is always 0. If it is a
 * user space stack trace (u_stack_trace_id), the PID is
 * the PID of the user process.
 */
void *get_symbol_cache(pid_t pid, bool new_cache)
{
	ASSERT(pid >= 0);

	if (k_resolver == NULL && pid == 0) {
		symbolizer_kernel_lock();
		if (k_resolver == NULL) {
			k_resolver = (void *)bcc_symcache_new(-1, &lazy_opt);
			sys_btime_msecs = get_sys_btime_msecs();
		}
		symbolizer_kernel_unlock();
	}

	if (!new_cache)
		return NULL;

	if (pid == 0)
		return k_resolver;

	symbol_caches_hash_t *h = &syms_cache_hash;
	struct symbolizer_proc_info *p;
	struct symbolizer_cache_kvp kv;
	kv.k.pid = (u64) pid;
	kv.v.proc_info_p = 0;
	if (symbol_caches_hash_search(h, (symbol_caches_hash_kv *) & kv,
				      (symbol_caches_hash_kv *) & kv) == 0) {
		p = (struct symbolizer_proc_info *)kv.v.proc_info_p;
		AO_INC(&p->use);
		symbolizer_proc_lock(p);
		u64 curr_time = current_sys_time_secs();
		if (p->verified) {
			/*
			 * If an unknown frame appears during the process of symbolizing
			 * the address of the Java process, we need to re-obtain the sy-
			 * mbols table of the Java process after a delay.
			 */
			if ((p->unknown_syms_found
			     || (void *)p->syms_cache == NULL)
			    && p->update_syms_table_time == 0) {
				/*
				 * If an exception occurs during the process of generating
				 * the Java symbol table, such as a failure to establish a
				 * connection with the target JVM, the symbol file will not
				 * be generated. In this case, no further symbol requests will
				 * be made to this Java process.
				 * Control with 'p->gen_java_syms_file_err'
				 */
				if (p->is_java
				    && (p->unknown_syms_found
					|| p->gen_java_syms_file_err)) {
					p->update_syms_table_time =
					    curr_time +
					    get_java_syms_fetch_delay();
				}

				/*
				 * When the deepflow-agent is started, to avoid the sudden
				 * generation of Java symbol tables, additional random value
				 * for each java process's delay.
				 */
				if (p->syms_cache == 0
				    && !p->gen_java_syms_file_err) {
					p->update_syms_table_time =
					    generate_random_integer
					    (PROFILER_DEFER_RANDOM_MAX);
				}
			}

			if (p->update_syms_table_time > 0
			    && curr_time >= p->update_syms_table_time) {
				if (p->is_java) {
					java_expired_update(h, &kv, p);
					symbolizer_proc_unlock(p);
					AO_DEC(&p->use);
					return (void *)p->syms_cache;
				} else {
					void *ret =
					    symbols_cache_update(h, &kv, p);
					symbolizer_proc_unlock(p);
					AO_DEC(&p->use);
					return ret;
				}
			}
		} else {
			symbolizer_proc_unlock(p);
			AO_DEC(&p->use);
			/* Ensure that newly launched JAVA processes are detected. */
			return NULL;
		}

		if (p->syms_cache) {
			symbolizer_proc_unlock(p);
			AO_DEC(&p->use);
			return (void *)p->syms_cache;
		}

		symbolizer_proc_unlock(p);
		AO_DEC(&p->use);
	}

	return NULL;
}

int create_and_init_proc_info_caches(void)
{
	/*
	 * Building a 'proc_event_ring' for handling process events.
	 * Enabling a multi-producer, single-consumer (MPSC) model.
	 */
	proc_event_ring = ring_create("proc-event-ring", PROC_RING_SZ,
				      SOCKET_ID_ANY, RING_F_SC_DEQ);
	if (proc_event_ring == NULL) {
		ebpf_warning("<%s> ring_create fail. err:%s\n", __func__,
			     strerror(errno));
		return ETR_NOMEM;
	}

	init_symbol_cache("symbolizer-caches");
	struct dirent *entry = NULL;
	DIR *fddir = NULL;

	fddir = opendir("/proc/");
	if (fddir == NULL) {
		ebpf_warning("Failed to open '/proc'\n");
		return ETR_PROC_FAIL;
	}

	pid_t pid;
	symbol_caches_hash_t *h = &syms_cache_hash;
	while ((entry = readdir(fddir)) != NULL) {
		pid = atoi(entry->d_name);
		if (entry->d_type == DT_DIR && pid > 0 && is_process(pid)) {
			struct symbolizer_cache_kvp sym;
			sym.k.pid = pid;

			struct symbolizer_proc_info *p =
			    clib_mem_alloc_aligned("sym_proc_info",
						   sizeof(struct
							  symbolizer_proc_info),
						   0, NULL);
			if (p == NULL) {
				/* exit process */
				ebpf_error
				    ("Failed to build process information table.\n");
				return ETR_NOMEM;
			}

			if (config_symbolizer_proc_info(p, pid) != ETR_OK) {
				clib_mem_free(p);
				continue;
			}

			sym.v.proc_info_p = pointer_to_uword(p);
			if (symbol_caches_hash_add_del
			    (h, (symbol_caches_hash_kv *) & sym,
			     1 /* is_add */ )) {
				ebpf_warning
				    ("symbol_caches_hash_add_del() failed.(pid %d)\n",
				     pid);
			} else {
				ebpf_debug
				    ("Process '%s'(pid %d start time %lu) has been"
				     " brought under management.\n",
				     p->comm, pid, p->stime);
				__sync_fetch_and_add(&h->hash_elems_count, 1);
			}
		}
	}

	closedir(fddir);
	return ETR_OK;
}

static int __unused free_symbolizer_kvp_cb(symbol_caches_hash_kv * kv,
					   void *ctx)
{
	struct symbolizer_cache_kvp *sym = (struct symbolizer_cache_kvp *)kv;
	free_symbolizer_cache_kvp(sym);
	(*(u64 *) ctx)++;
	return BIHASH_WALK_CONTINUE;
}

void release_symbol_caches(void)
{
	/* Update symbol_cache hash from pids_cache. */
	//exec_proc_info_cache_update();

	/*
	 * Due to socket data being queried by this hash, there is no synchronization
	 * protection here. release_symbol_caches() is called only for testing purposes,
	 * so ensure smooth testing, let's temporarily remove the code for releasing
	 * hash resources.
	 * TODO(@jiping), add a synchronization lock for protection.
	 */

#if 0
	/* user symbol caches release */
	u64 elems_count = 0;
	symbol_caches_hash_t *h = &syms_cache_hash;
	ebpf_info("Release symbol_caches %lu elements\n", h->hash_elems_count);

	symbol_cache_pids_lock();
	symbol_caches_hash_foreach_key_value_pair(h,
						  free_symbolizer_kvp_cb,
						  (void *)&elems_count);
	print_hash_symbol_caches(h);
	symbol_caches_hash_free(h);
	ebpf_info
	    ("Clear symbol_caches_hashmap[k:pid, v:symbol cache] %lu elems.\n",
	     elems_count);

	/* kernel symbol caches release */
	if (k_resolver) {
		bcc_free_symcache(k_resolver, -1);
		k_resolver = NULL;
	}
	symbol_cache_pids_unlock();

	ebpf_info
	    ("+++ add_symcache_count : %lu free_symcache_count : %lu +++\n",
	     add_symcache_count, free_symcache_count);

	/*
	 * The malloc_trim() function tries to reclaim unused memory blocks by
	 * examining the top of memory blocks and then returns them to the system.
	 * This helps reduce the amount of physical memory used by the process,
	 * thus optimizing memory usage.
	 */
	//malloc_trim(0);
#endif
}

int creat_ksyms_cache(void)
{
	errno = 0;
	symbolizer_kernel_lock();
	k_resolver = (void *)bcc_symcache_new(-1, &lazy_opt);
	sys_btime_msecs = get_sys_btime_msecs();
	symbolizer_kernel_unlock();
	if (k_resolver == NULL) {
		ebpf_warning("symcache create error, errno %d : %s\n", errno,
			     strerror(errno));
		return -1;
	}
	u64 test_addr = kallsyms_lookup_name("__sys_sendmsg");
	if (test_addr == 0) {
		ebpf_warning("Symbol '__sys_sendmsg', not find.\n");
		return -1;
	}

	struct bcc_symbol sym = {};
	bcc_symcache_resolve_no_demangle(k_resolver, test_addr, &sym);
	if (strcmp(sym.name, "__sys_sendmsg")) {
		ebpf_warning
		    ("address 0x%lx target symbol '__sys_sendmsg', "
		     "but find symbol is %s.\n", test_addr, sym.name);
		return -1;
	}

	ebpf_info("address 0x%lx find symbol '__sys_sendmsg', "
		  "ksyms-cache, created successfully.\n", test_addr);
	return 0;
}

#else /* defined AARCH64_MUSL */
/* pid : The process ID (PID) that occurs when a process exits. */
void update_proc_info_cache(pid_t pid, enum proc_act_type type)
{
	return;
}

void get_container_id_from_procs_cache(pid_t pid, uint8_t * id, int id_size)
{
	memset(id, 0, id_size);
	fetch_container_id(pid, id, id_size);
}

int create_and_init_proc_info_caches(void)
{
	return 0;
}

void exec_proc_info_cache_update(void)
{
}

#endif /* AARCH64_MUSL */
