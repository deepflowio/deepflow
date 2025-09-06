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
#include <ctype.h>
#include <linux/version.h>
#include "config.h"
#include "elf.h"
#include "log.h"
#include "utils.h"
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
#include "profile/java/jvm_symbol_collect.h"
#include "profile/java/collect_symbol_files.h"
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

static struct bcc_symbol_option lazy_opt = {
	.use_debug_file = false,
	.check_debug_file_crc = false,
	.lazy_symbolize = true,
	.use_symbol_type = ((1 << STT_FUNC) | (1 << STT_GNU_IFUNC)),
};

static int config_symbolizer_proc_info(struct symbolizer_proc_info *p, int pid);

u64 get_proc_exec_event_count(void)
{
	return AO_GET(&proc_exec_event_count);
}

u64 get_proc_exit_event_count(void)
{
	return AO_GET(&proc_exit_event_count);
}

void clear_proc_exec_event_count(void)
{
	AO_SET(&proc_exec_event_count, 0);
}

void clear_proc_exit_event_count(void)
{
	AO_SET(&proc_exit_event_count, 0);
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
	int pid = (int)p->pid;
	if (p->is_java) {
		/* Delete target ns Java files */
		if (pid > 0) {
			clean_local_java_symbols_files(pid);
		}
	}

	if (p->syms_cache) {
		bcc_free_symcache((void *)p->syms_cache, p->pid);
		free_symcache_count++;
	}

	vec_free(p->thread_names);
	p->thread_names = NULL;
	p->syms_cache = 0;
	mount_info_cache_remove(pid, p->mntns_id);
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

static inline struct symbolizer_proc_info *add_proc_info_to_cache(struct
								  symbolizer_cache_kvp
								  *kv)
{
	pid_t pid = (pid_t) kv->k.pid;
	if (kv->v.proc_info_p) {
		free_symbolizer_cache_kvp(kv);
		kv->k.pid = pid;
		kv->v.proc_info_p = 0;
	}
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
		__sync_fetch_and_add(&h->hash_elems_count, 1);
		// Associate mount information when a new process starts.
		mount_info_cache_add_if_absent(pid, p->mntns_id);
	}

	return p;
}

static inline int __del_proc_info_from_cache(struct symbolizer_cache_kvp *kv)
{
	symbol_caches_hash_t *h = &syms_cache_hash;
	if (symbol_caches_hash_search(h, (symbol_caches_hash_kv *) kv,
				      (symbol_caches_hash_kv *) kv) == 0) {
		struct symbolizer_proc_info *p;
		p = (struct symbolizer_proc_info *)kv->v.proc_info_p;
		if (p != NULL) {
			AO_INC(&p->use);
			p->is_exit = 1;
			AO_DEC(&p->use);
		}

		if (symbol_caches_hash_add_del
		    (h, (symbol_caches_hash_kv *) kv, 0 /* delete */ )) {
			ebpf_warning("failed.(pid %d)\n", (pid_t) kv->k.pid);
			return -1;
		} else {
			__sync_fetch_and_add(&h->hash_elems_count, -1);
			if (p)
				free_symbolizer_cache_kvp(kv);
			return 0;
		}
	} else {
		ebpf_debug
		    ("The process with PID %d does not exist in the cache."
		     " Failed to clean up process information.\n", kv->k.pid);
	}

	return -1;
}

static int del_proc_info_from_cache(struct symbolizer_cache_kvp *kv)
{
	/*
	 * Note that the entry has already been removed from the hash cache before
	 * calling del_proc_info_from_cache(). This step performs cleanup of the associated data.
	 */
	pid_t pid = (pid_t) kv->k.pid;
	if (kv->v.proc_info_p) {
		free_symbolizer_cache_kvp(kv);
		kv->k.pid = pid;
		kv->v.proc_info_p = 0;
	}

	/*
	 * To prevent a scenario where Process A exits and Process B starts immediately
	 * afterward using the same PID — and then Process B also exits — we perform an
	 * extra safety check here.
	 */
	__del_proc_info_from_cache(kv);
	return 0;
}

int get_proc_info_from_cache(pid_t pid, uint8_t * cid, int cid_size,
			     uint8_t * name, int name_size, kern_dev_t s_dev,
			     char *mount_point, char *mount_source,
			     int mount_size, bool * is_nfs)
{
	symbol_caches_hash_t *h = &syms_cache_hash;
	struct symbolizer_cache_kvp kv;
	kv.k.pid = (u64) pid;
	kv.v.proc_info_p = 0;
	memset(cid, 0, cid_size);
	memset(name, 0, name_size);
	memset(mount_point, 0, mount_size);
	memset(mount_source, 0, mount_size);
	struct symbolizer_proc_info *p = NULL;
	if (symbol_caches_hash_search(h, (symbol_caches_hash_kv *) & kv,
				      (symbol_caches_hash_kv *) & kv) == 0) {
		p = (struct symbolizer_proc_info *)kv.v.proc_info_p;
		AO_INC(&p->use);
		if (strlen(p->container_id) > 0) {
			memcpy_s_inline((void *)cid, cid_size, p->container_id,
					sizeof(p->container_id));
		}

		if (strlen(p->comm) > 0) {
			memcpy_s_inline((void *)name, name_size, p->comm,
					sizeof(p->comm));
		}
		if (s_dev != DEV_INVALID)
			find_mount_point_path(pid, &p->mntns_id, s_dev,
					      mount_point, mount_source,
					      mount_size, is_nfs);
		AO_DEC(&p->use);
		return 0;
	}

	return -1;
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
		ebpf_info("Could not add process %d to proc_event_ring\n",
			  kv->k.pid);
		return -1;
	}

	return 0;
}

static void add_proc_event_to_queue(pid_t pid, enum proc_act_type type)
{
	symbol_caches_hash_t *h = &syms_cache_hash;
	struct symbolizer_cache_kvp kv = {};
	kv.k.pid = (u64) pid;
	kv.v.proc_info_p = 0;
	if (type == PROC_EXEC) {
		__sync_fetch_and_add(&proc_exec_event_count, 1);
	} else {
		__sync_fetch_and_add(&proc_exit_event_count, 1);
	}

	if (symbol_caches_hash_search(h, (symbol_caches_hash_kv *) & kv,
				      (symbol_caches_hash_kv *) & kv) == 0) {
		struct symbolizer_proc_info *p;
		p = (struct symbolizer_proc_info *)kv.v.proc_info_p;
		if (p != NULL) {
			AO_INC(&p->use);
			p->is_exit = 1;
			AO_DEC(&p->use);
		}

		if (symbol_caches_hash_add_del
		    (h, (symbol_caches_hash_kv *) & kv, 0 /* delete */ )) {
			ebpf_warning("failed.(pid %d)\n", (pid_t) kv.k.pid);
			return;
		} else {
			__sync_fetch_and_add(&h->hash_elems_count, -1);
		}
	}

	add_proc_ev_info_to_ring(type, &kv);
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

	add_proc_event_to_queue(pid, type);
}

void exec_proc_info_cache_update(void)
{
	if (proc_event_ring == NULL)
		return;
	int nr;
	void *rx_burst[MAX_EVENTS_BURST];
	do {
		nr = ring_sc_dequeue_burst(proc_event_ring, rx_burst,
					   MAX_EVENTS_BURST, NULL);
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
}

static int init_symbol_cache(const char *name)
{
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
	p->need_new_symbol_collector = true;
	p->lock = 0;
	pthread_mutex_init(&p->mutex, NULL);
	p->syms_cache = 0;
	p->thread_names = NULL;
	p->thread_names_lock = 0;
	p->netns_id = get_netns_id_from_pid(pid);

	fetch_container_id_from_proc(pid, p->container_id,
				     sizeof(p->container_id));

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

	get_mount_ns_id(pid, &p->mntns_id);
	mount_info_cache_add_if_absent(pid, p->mntns_id);
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

	if (p->need_new_symbol_collector)
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
				} else {
					p->update_syms_table_time = curr_time;
				}

				/*
				 * When the deepflow-agent is started, to avoid the sudden
				 * generation of Java symbol tables, additional random value
				 * for each java process's delay.
				 * The same applies to non-Java processes, which also perform
				 * random symbol table loading within one minute.
				 */
				p->update_syms_table_time +=
				    generate_random_integer
				    (PROFILER_DEFER_RANDOM_MAX);
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
	// Initialize the mount information cache.
	mount_info_cache_init("mount-info-cache");

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

struct symbolizer_cache_kvp *clear_procs;
struct mntns_pid_s {
	pid_t pid;
	u64 mntns_id;
};
struct mntns_pid_s *mntns_id_list;
static inline void insert_mntns_vecs(struct mntns_pid_s *mp)
{
	struct mntns_pid_s *m;
	vec_foreach(m, mntns_id_list) {
		if (m->mntns_id == mp->mntns_id)
			return;
	}

	int ret = VEC_OK;
	vec_add1(mntns_id_list, *mp, ret);
	if (ret != VEC_OK) {
		ebpf_warning("vec add failed.\n");
	}
}

static int check_proc_kvp_cb(symbol_caches_hash_kv * kvp, void *ctx)
{
	struct symbolizer_cache_kvp *kv = (struct symbolizer_cache_kvp *)kvp;
	pid_t pid = 0;
	bool del_proc = false;
	struct symbolizer_proc_info *p = NULL;
	if (kv->v.proc_info_p) {
		p = (struct symbolizer_proc_info *)kv->v.proc_info_p;
		AO_INC(&p->use);
		pid = p->pid;
		if ((p->stime == 0) ||
		    (p->stime != 0 && p->stime != get_process_starttime(pid))) {
			p->is_exit = 1;
			del_proc = true;
		}
		AO_DEC(&p->use);
	}

	if (p) {
		int ret = VEC_OK;
		if (del_proc) {
			vec_add1(clear_procs, *kv, ret);
			if (ret != VEC_OK) {
				ebpf_warning("vec add failed.\n");
			}
		}
		struct mntns_pid_s mp;
		mp.pid = p->pid;
		mp.mntns_id = p->mntns_id;
		insert_mntns_vecs(&mp);
	}

	(*(u64 *) ctx)++;
	return BIHASH_WALK_CONTINUE;
}

void check_and_update_proc_info(bool output_log)
{
	u64 elems_count = 0, clear_count = 0;
	struct symbolizer_cache_kvp *kv;
	symbol_caches_hash_t *h = &syms_cache_hash;
	symbol_caches_hash_foreach_key_value_pair(h,
						  check_proc_kvp_cb,
						  (void *)&elems_count);
	vec_foreach(kv, clear_procs) {
		if (__del_proc_info_from_cache(kv) == 0)
			clear_count++;
	}
	vec_free(clear_procs);

	struct mntns_pid_s *m;
	vec_foreach(m, mntns_id_list) {
		check_and_cleanup_mount_info(m->pid, m->mntns_id);
	}
	vec_free(mntns_id_list);

	if (clear_count > 0 || output_log)
		ebpf_info("Checked %d entries in the process cache and "
			  "cleaned up %d invalid process records.\n",
			  elems_count, clear_count);
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

void check_and_update_proc_info(bool output_log)
{
}

int get_proc_info_from_cache(pid_t pid, uint8_t * cid, int cid_size,
			     uint8_t * name, int name_size, kern_dev_t s_dev,
			     char *mount_point, char *mount_source,
			     int mount_size, bool * is_nfs)
{
	memset(cid, 0, cid_size);
	memset(name, 0, name_size);
	memset(mount_point, 0, mount_size);
	memset(mount_source, 0, mount_size);
	*is_nfs = false;
	return -1;
}

int create_and_init_proc_info_caches(void)
{
	return 0;
}

void exec_proc_info_cache_update(void)
{
}

#endif /* AARCH64_MUSL */

extern uint32_t k_version;

// Lower version kernels do not support hooking so files in containers
bool kernel_version_check(void)
{
	bool ret = ((k_version == KERNEL_VERSION(3, 10, 0))
		    || (k_version >= KERNEL_VERSION(4, 17, 0)));
	if (!ret)
		ebpf_warning("UPROBE feature requires linux "
			     "version of 3.10 or 4.17+.\n");

	return ret;
}

bool process_probing_check(int pid)
{
	char c_id[65];
	memset(c_id, 0, sizeof(c_id));
	// Linux 3.10.0 kernel does not support probing files in containers.
	if ((k_version == KERNEL_VERSION(3, 10, 0)) &&
	    (fetch_container_id_from_proc(pid, c_id, sizeof(c_id)) == 0))
		return false;

	return true;
}

void process_event_free(struct process_create_event *event)
{
	if (event == NULL) {
		ebpf_warning("The event is empty.\n");
		return;
	}

	if (event->path)
		free(event->path);

	free(event);
}

void add_event_to_proc_list(proc_event_list_t * list, struct bpf_tracer *tracer,
			    int pid, char *path)
{
	static const uint32_t PROC_EVENT_HANDLE_DELAY = 120;
	struct process_create_event *event = NULL;

	event = calloc(1, sizeof(struct process_create_event));
	if (!event) {
		ebpf_warning("no memory.\n");
		return;
	}

	event->tracer = tracer;
	event->pid = pid;
	event->stime = get_process_starttime(pid);
	event->path = path;
	event->expire_time = get_sys_uptime() + PROC_EVENT_HANDLE_DELAY;

	pthread_mutex_lock(&list->m);
	list_add_tail(&event->list, &list->head);
	pthread_mutex_unlock(&list->m);
}

struct process_create_event *get_first_event(proc_event_list_t * list)
{
	struct process_create_event *event = NULL;
	pthread_mutex_lock(&list->m);
	if (!list_empty(&list->head)) {
		event = list_first_entry(&list->head,
					 struct process_create_event, list);
	}
	pthread_mutex_unlock(&list->m);
	return event;
}

void remove_event(proc_event_list_t * list, struct process_create_event *event)
{
	pthread_mutex_lock(&list->m);
	list_head_del(&event->list);
	pthread_mutex_unlock(&list->m);
}

// https://github.com/iovisor/bcc/blob/15fccdb9a4dbdc3d41e669a7ad5be73d2ac44b00/src/cc/bcc_proc.c#L419
static int which_so_in_process(const char *libname, int pid, char *libpath)
{
	int ret, found = 0;
	char endline[4096], *mapname = NULL, *newline;
	char mappings_file[128];
	const size_t search_len = strlen(libname) + strlen("/lib.");
	char search1[search_len + 1];
	char search2[search_len + 1];

	snprintf(mappings_file, sizeof(mappings_file), "/proc/%ld/maps",
		 (long)pid);
	FILE *fp = fopen(mappings_file, "r");
	if (!fp)
		return found;

	snprintf(search1, search_len + 1, "/lib%s.", libname);
	snprintf(search2, search_len + 1, "/lib%s-", libname);

	do {
		ret = fscanf(fp, "%*x-%*x %*s %*x %*s %*d");
		if (!fgets(endline, sizeof(endline), fp))
			break;

		mapname = endline;
		newline = strchr(endline, '\n');
		if (newline)
			newline[0] = '\0';

		while (isspace(mapname[0]))
			mapname++;

		if (strstr(mapname, ".so") &&
		    (strstr(mapname, search1) || strstr(mapname, search2))) {
			found = 1;
			memcpy(libpath, mapname, strlen(mapname) + 1);
			break;
		}
	} while (ret != EOF);

	fclose(fp);
	return found;
}

bool check_so_path_by_pid_and_name(int pid, const char *so_name)
{
	char so_path[PATH_MAX] = { 0 };

	int offset = snprintf(so_path, sizeof(so_path), "/proc/%d/root", pid);
	if (offset < 0 || offset >= sizeof(so_path))
		return NULL;

	return which_so_in_process(so_name, pid, so_path + offset) != 0;
}

char *get_so_path_by_pid_and_name(int pid, const char *so_name)
{
	int ret = 0;
	char so_path[PATH_MAX] = { 0 };

	int offset = snprintf(so_path, sizeof(so_path), "/proc/%d/root", pid);
	if (offset < 0 || offset >= sizeof(so_path))
		return NULL;

	ret = which_so_in_process(so_name, pid, so_path + offset);
	if (!ret)
		return NULL;
	return strdup(so_path);
}

#if defined(__powerpc64__) && defined(_CALL_ELF) && _CALL_ELF == 2
#define bcc_use_symbol_type (65535 | (1 << STT_PPC64_ELFV2_SYM_LEP))
#else
#define bcc_use_symbol_type (65535)
#endif

static struct bcc_symbol_option bcc_elf_foreach_sym_option = {
	.use_debug_file = 0,
	.check_debug_file_crc = 0,
	.lazy_symbolize = 1,
	.use_symbol_type = bcc_use_symbol_type,
};

struct bcc_elf_foreach_sym_payload {
	uint64_t addr;
	uint64_t size;
	const char *name;
	const char *prefix;
	const char *symbol_name;
};

static int bcc_elf_foreach_sym_callback(const char *name, uint64_t addr,
					uint64_t size, void *payload)
{
	struct bcc_elf_foreach_sym_payload *p = payload;
	char *pos;
	if (p->name && (pos = strstr(name, p->name))) {
		if (pos[strlen(p->name)] == '\0') {
			p->addr = addr;
			p->size = size;
			p->symbol_name = strdup(name);
			return -1;
		}
	} else if (p->prefix && (pos = strstr(name, p->prefix))) {
		if (name == pos) {
			p->addr = addr;
			p->size = size;
			p->symbol_name = strdup(name);
			return -1;
		}
	}
	return 0;
}

int add_probe_sym_to_tracer_probes(int pid, const char *path,
				   struct tracer_probes_conf *conf,
				   struct symbol symbols[], size_t n_symbols)
{
	int ret, idx, count;
	ret = idx = count = 0;
	struct symbol_uprobe *probe_sym = NULL;
	struct symbol *cur = NULL;
	struct bcc_elf_foreach_sym_payload payload;

	for (idx = 0; idx < n_symbols; ++idx) {
		memset(&payload, 0, sizeof(payload));
		cur = &symbols[idx];

		// Use memory on the stack, no need to allocate on the heap
		payload.name = cur->symbol;
		payload.prefix = cur->symbol_prefix;
		ret = bcc_elf_foreach_sym(path, bcc_elf_foreach_sym_callback,
					  &bcc_elf_foreach_sym_option,
					  &payload);
		if (ret)
			break;

		// It has been confirmed earlier that the incoming binary file
		// must be libssl.so and should not be hit here
		if (!payload.addr || !payload.size)
			continue;

		// This memory will be maintained in conf, no need to release
		probe_sym = calloc(1, sizeof(struct symbol_uprobe));
		if (!probe_sym)
			continue;

		// Data comes from symbolic information
		probe_sym->entry = payload.addr;
		probe_sym->size = payload.size;

		// Data comes from global variables
		probe_sym->type = cur->type;
		probe_sym->isret = cur->is_probe_ret;
		probe_sym->probe_func = strdup(cur->probe_func);
		probe_sym->name = payload.symbol_name;

		// Data comes from function input parameters
		probe_sym->binary_path = strdup(path);
		probe_sym->pid = pid;

		/*
		 * For executable binary files (ET_EXEC), convert the virtual
		 * address to a physical address.
		 * For shared library binary files (ET_DYN), no conversion is needed.
		 * ref: https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html
		 */
		if (bcc_elf_get_type(probe_sym->binary_path) == ET_EXEC) {
			struct load_addr_t addr = {
				.target_addr = probe_sym->entry,
				.binary_addr = 0x0,
			};

			if (bcc_elf_foreach_load_section
			    (probe_sym->binary_path, &find_load, &addr) < 0) {
				goto invalid;
			}
			if (!addr.binary_addr) {
				goto invalid;
			}
			probe_sym->entry = addr.binary_addr;
		}

		if (probe_sym->probe_func && probe_sym->name &&
		    probe_sym->binary_path) {
			add_uprobe_symbol(pid, probe_sym, conf);
		} else {
			goto invalid;
		}

		count++;
		continue;

	      invalid:
		free((void *)probe_sym->probe_func);
		free((void *)probe_sym->name);
		free((void *)probe_sym->binary_path);
		free(probe_sym);
	}

	return count;
}
