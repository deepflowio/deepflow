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
#include "log.h"
#include "common.h"
#include "symbol.h"
#include "tracer.h"
#if defined __x86_64__
#include "bddisasm/bddisasm.h"
#include "bddisasm/disasmtypes.h"
#endif
#include "libGoReSym.h"
#include "profile/java/df_jattach.h"
#include "profile/attach.h"

static u64 add_symcache_count;
static u64 free_symcache_count;

/*
 * To allow Java to run for an extended period and gather more symbol
 * information, we delay symbol retrieval when encountering unknown symbols.
 * The default value is 'JAVA_SYMS_UPDATE_DELAY_DEF'.
 */
static volatile u64 java_syms_fetch_delay; // In seconds.
   
/*
 * When a process exits, save the symbol cache pids
 * to be deleted.
 */
static struct symbol_cache_del_pids cache_del_pids;

void set_java_syms_fetch_delay(int delay_secs)
{
	java_syms_fetch_delay = delay_secs;
}

u64 get_java_syms_fetch_delay(void)
{
	return java_syms_fetch_delay;
}

void free_uprobe_symbol(struct symbol_uprobe *u_sym,
			struct tracer_probes_conf *conf)
{
	if (u_sym == NULL)
		return;

	if (u_sym->list.prev != NULL && u_sym->list.next != NULL) {
		list_head_del(&u_sym->list);
		if (conf)
			conf->uprobe_count--;
	}

	if (u_sym->name)
		free((void *)u_sym->name);
	if (u_sym->binary_path)
		free((void *)u_sym->binary_path);
	if (u_sym->probe_func)
		free((void *)u_sym->probe_func);

	free(u_sym);
}

void add_uprobe_symbol(int pid, struct symbol_uprobe *u_sym,
		       struct tracer_probes_conf *conf)
{
	u_sym->starttime = get_process_starttime(pid);
	u_sym->in_probe = false;
	list_add_tail(&u_sym->list, &conf->uprobe_syms_head);
	conf->uprobe_count++;
}

int copy_uprobe_symbol(struct symbol_uprobe *src, struct symbol_uprobe *dst)
{
	if (src == NULL || dst == NULL)
		return ETR_NOTEXIST;

	memcpy((void *)dst, src, sizeof(struct symbol_uprobe));
	dst->name = dst->binary_path = dst->probe_func = NULL;
	if (src->name) {
		dst->name = strdup(src->name);
		if (dst->name == NULL)
			goto failed;
	}

	if (src->binary_path) {
		dst->binary_path = strdup(src->binary_path);
		if (dst->binary_path == NULL)
			goto failed;
	}

	if (src->probe_func) {
		dst->probe_func = strdup(src->probe_func);
		if (dst->probe_func == NULL)
			goto failed;
	}

	return ETR_OK;

failed:
	if (dst->name) {
		zfree(dst->name);
	}

	if (dst->binary_path) {
		zfree(dst->binary_path);
	}

	if (dst->probe_func) {
		zfree(dst->probe_func);
	}

	return ETR_NOMEM;
}

static int find_sym(const char *symname, uint64_t addr, uint64_t size,
		    void *payload)
{
	struct symbol_uprobe *sym = (struct symbol_uprobe *)payload;
	char *pos;
	if ((pos = strstr(symname, sym->name))) {
		if (pos[strlen(sym->name)] == '\0') {
			sym->entry = addr;
			sym->size = size;
			return -1;
		}
	}
	return 0;
}

int find_load(uint64_t v_addr, uint64_t mem_sz, uint64_t file_offset,
	      void *payload)
{
	struct load_addr_t *addr = (struct load_addr_t *)payload;

	if (addr->target_addr >= v_addr
	    && addr->target_addr < (v_addr + mem_sz)) {
		addr->binary_addr = addr->target_addr - v_addr + file_offset;
		return -1;
	}

	return 0;
}

#if defined __x86_64__
static void resolve_func_ret_addr(struct symbol_uprobe *uprobe_sym)
{
	NDSTATUS status;
	INSTRUX ix;
	int fd;
	size_t pc;
	int remian;
	int cnt = 0;
	size_t offset = 0;
	char *buffer = NULL;

	fd = open(uprobe_sym->binary_path, O_RDONLY);
	if (fd == -1)
		goto out;

	if (lseek(fd, uprobe_sym->entry, SEEK_SET) == -1)
		goto close_file;

	buffer = malloc(uprobe_sym->size);
	if (!buffer)
		goto close_file;

	if (read(fd, buffer, uprobe_sym->size) == -1)
		goto free_buffer;

	memset(uprobe_sym->rets, 0, sizeof(uprobe_sym->rets));
	pc = uprobe_sym->entry;
	while (offset < uprobe_sym->size && cnt < FUNC_RET_MAX) {
		remian = uprobe_sym->size - offset;
		status = NdDecodeEx(&ix, (ND_UINT8 *) (buffer + offset), remian,
				    ND_CODE_64, ND_DATA_64);
		if (!ND_SUCCESS(status))
			break;

		if (ix.Instruction == ND_INS_RETF ||
		    ix.Instruction == ND_INS_RETN) {
			uprobe_sym->rets[cnt++] = pc;
		}
		offset += ix.Length;
		pc += ix.Length;
	}

free_buffer:
	free(buffer);
close_file:
	close(fd);
out:
	uprobe_sym->rets_count = cnt;
}
#endif

#if defined __aarch64__
// https://developer.arm.com/documentation/ddi0596/2020-12/Base-Instructions/RET--Return-from-subroutine-
static int is_a64_ret_ins(unsigned int code)
{
	return (code & 0xfffffc1f) == 0xd65f0000;
}

static void resolve_func_ret_addr(struct symbol_uprobe *uprobe_sym)
{
	static const int ARM64_INS_LEN = 4;
	int fd = 0;
	int cnt = 0;
	size_t offset = 0;
	char *buffer = NULL;
	uint32_t code = 0;

	fd = open(uprobe_sym->binary_path, O_RDONLY);
	if (fd == -1)
		goto out;

	if (lseek(fd, uprobe_sym->entry, SEEK_SET) == -1)
		goto close_file;

	buffer = malloc(uprobe_sym->size);
	if (!buffer)
		goto close_file;

	if (read(fd, buffer, uprobe_sym->size) == -1)
		goto free_buffer;

	memset(uprobe_sym->rets, 0, sizeof(uprobe_sym->rets));
	while (cnt < FUNC_RET_MAX && offset <= uprobe_sym->size - ARM64_INS_LEN) {
		code = *(uint32_t *) (buffer + offset);
		if (is_a64_ret_ins(code)) {
			uprobe_sym->rets[cnt++] = uprobe_sym->entry + offset;
		}
		offset += ARM64_INS_LEN;
	}

free_buffer:
	free(buffer);
close_file:
	close(fd);
out:
	uprobe_sym->rets_count = cnt;
}
#endif

static struct bcc_symbol_option default_option = {
	.use_debug_file = 1,
	.check_debug_file_crc = 1,
	.lazy_symbolize = 1,
#if defined(__powerpc64__) && defined(_CALL_ELF) && _CALL_ELF == 2
	.use_symbol_type = 65535 | (1 << STT_PPC64_ELFV2_SYM_LEP),
#else
	.use_symbol_type = 65535,
#endif
};

/**
 * resolve_and_gen_uprobe_symbol -- 完成二进制文件中对给定符号的解析并生成uprobe_symbol
 * @bin_file: 二进制文件，如果是可执行文件需要指定文件的全路径,
 * 	      如果是库文件只需要给出库的名字即可,
 *            例如：libssl.so 只需提供名字"ssl"。
 * @sym: 符号信息。
 * @addr: 目标地址。非0，已经给定不需要bcc_elf_foreach_sym()进行获取了，否则需要遍历符号表。
 * @pid: 用于在指定的进程中查找使用的库(/proc/<pid>/maps)。
 * 返回值：
 *   成功返回0，失败返回非0
 */
struct symbol_uprobe *resolve_and_gen_uprobe_symbol(const char *bin_file,
						    struct symbol *sym,
						    const uint64_t addr,
						    int pid)
{
	if (bin_file == NULL) {
		ebpf_warning("bin_file == NULL, failed.\n");
		return NULL;
	}

	struct symbol_uprobe *uprobe_sym =
	    calloc(1, sizeof(struct symbol_uprobe));
	if (uprobe_sym == NULL) {
		ebpf_warning("uprobe_sym = calloc() failed.\n");
		return NULL;
	}

	uprobe_sym->type = sym->type;
	uprobe_sym->isret = sym->is_probe_ret;
	uprobe_sym->pid = pid;
	uprobe_sym->probe_func = strdup(sym->probe_func);
	if (uprobe_sym->probe_func == NULL) {
		ebpf_warning("strdup() failed.\n");
		goto invalid;
	}

	/*
	 * 判断是可执行目标文件还是库文件。
	 */
	if (strchr(bin_file, '/'))
		uprobe_sym->binary_path = strdup(bin_file);
	else
		/*
		 * 从”/proc/<pid>/maps“和"/etc/ld.so.cache"查找
		 * "lib<libname>.so"绝对路径
		 */
		uprobe_sym->binary_path = bcc_procutils_which_so(bin_file, pid);

	if (uprobe_sym->binary_path == NULL) {
		ebpf_warning("uprobe_sym->binary_path == NULL\n");
		goto invalid;
	}

	uprobe_sym->name = strdup(sym->symbol);
	if (uprobe_sym->name == NULL) {
		ebpf_warning("uprobe_sym->name == NULL\n");
		goto invalid;
	}

	uprobe_sym->entry = addr;

	if (uprobe_sym->name && uprobe_sym->entry == 0x0) {
		int error = 0;
		error = bcc_elf_foreach_sym(uprobe_sym->binary_path, find_sym,
					    &default_option, uprobe_sym);

		if (!is_feature_enabled(FEATURE_UPROBE_GOLANG_SYMBOL) && error) {
			goto invalid;
		}
	}
	// If bcc_elf_foreach_sym is successful, uprobe_sym->entry will
	// not be 0. try GoReSym
	if (uprobe_sym->name && uprobe_sym->entry == 0x0 &&
	    is_feature_matched(FEATURE_UPROBE_GOLANG_SYMBOL,
			       uprobe_sym->binary_path)) {
		struct function_address_return func = {};
		func = function_address((char *)uprobe_sym->binary_path,
					(char *)uprobe_sym->name);
		uprobe_sym->entry = func.r0;
		uprobe_sym->size = func.r1;
	}

	if (uprobe_sym->entry == 0x0)
		goto invalid;

	/* 
	 * 对于可执行的二进制文件(ET_EXEC), 把virtual address转换成物理地址。
	 * 对应共享库二进制文件(ET_DYN), 不需要进行转换。
	 * https://refspecs.linuxbase.org/elf/gabi4+/ch5.pheader.html
	 */
	if (bcc_elf_get_type(uprobe_sym->binary_path) == ET_EXEC) {
		struct load_addr_t addr = {
			.target_addr = uprobe_sym->entry,
			.binary_addr = 0x0,
		};

		if (strstr(uprobe_sym->name, "go.itab.*")) {
			addr.binary_addr = addr.target_addr;
			uprobe_sym->entry = addr.binary_addr;
			return 0;
		}

		if (bcc_elf_foreach_load_section
		    (uprobe_sym->binary_path, &find_load, &addr) < 0) {
			goto invalid;
		}
		if (!addr.binary_addr) {
			goto invalid;
		}
		uprobe_sym->entry = addr.binary_addr;
	}

	if (uprobe_sym->isret && uprobe_sym->type == GO_UPROBE) {
		resolve_func_ret_addr(uprobe_sym);
	}

	return uprobe_sym;

invalid:
	free_uprobe_symbol(uprobe_sym, NULL);
	return NULL;
}

char *get_elf_path_by_pid(int pid)
{
#define PROC_PREFIX_LEN 32

	int ret, len;
	char bin_path[PATH_MAX], *path;
	char proc_pid_exe[PROC_PREFIX_LEN];
	memset(bin_path, 0, sizeof(bin_path));
	memset(proc_pid_exe, 0, sizeof(proc_pid_exe));

	if (snprintf(proc_pid_exe, sizeof(proc_pid_exe), "/proc/%d/exe", pid)
	    >= sizeof(proc_pid_exe)) {
		ebpf_warning("snprintf /proc/%d/exe failed", pid);
		return NULL;
	}
	ret = readlink(proc_pid_exe, bin_path, sizeof(bin_path));
	if (ret < 0) {
		return NULL;
	}

	len = strlen(bin_path) + PROC_PREFIX_LEN;
	path = calloc(1, len);
	if (path == NULL)
		return NULL;
	if (snprintf(path, len, "/proc/%d/root%s", pid, bin_path)
	    >= len) {
		ebpf_warning("snprintf /proc/%d/root%s failed", pid, bin_path);
		free(path);
		return NULL;
	}

	if (access(path, F_OK) != 0) {
		memset(path, 0, len);
		safe_buf_copy(path, len, bin_path, sizeof(bin_path));
	}

	return path;
}

#if defined(__x86_64__)
// The bddisasm library requires defined functions
void *nd_memset(void *s, int c, ND_SIZET n)
{
	return memset(s, c, n);
}
#endif

uint64_t get_symbol_addr_from_binary(const char *bin, const char *symname)
{
	if (!bin && !symname) {
		return 0;
	}

	struct symbol_uprobe tmp = {
		.name = symname,
		.entry = 0,
	};

	bcc_elf_foreach_sym(bin, find_sym, &default_option, &tmp);

	if (!tmp.entry && is_feature_matched(FEATURE_UPROBE_GOLANG_SYMBOL, bin)) {
		// The function address is used to set the hook point.
		// itab is used for http2 to obtain fd. Currently only
		// net_TCPConn_itab can be obtained for HTTPS.
		tmp.entry = itab_address((char *)bin, (char *)symname);
	}

	ebpf_info("Uprobe [%s] %s: %p\n", bin, symname, tmp.entry);
	return tmp.entry;
}

#ifndef AARCH64_MUSL
static symbol_caches_hash_t syms_cache_hash;	// for user process symbol caches
static void *k_resolver;	// for kernel symbol cache
static u64 sys_btime_msecs;	// system boot time(milliseconds)

static bool inline enable_symbol_cache(void)
{
	return (syms_cache_hash.buckets != NULL);
}

static inline void free_symbolizer_cache_kvp(struct symbolizer_cache_kvp *kv)
{
	if (kv->v.cache) {
		bcc_free_symcache((void *)kv->v.cache, kv->k.pid);
		free_symcache_count++;
		kv->v.cache = 0;
	}

	if (kv->v.proc_info_p) {
		struct symbolizer_proc_info *p;
		p = (struct symbolizer_proc_info *)kv->v.proc_info_p;
		if (p->is_java) {
			/* Delete target ns Java files */
			int pid = (int)kv->k.pid;
			if (pid > 0) {
				clean_local_java_symbols_files(pid);
			}
		}

		clib_mem_free((void *)p);
		kv->v.proc_info_p = 0;
	}
}

static inline void symbol_cache_pids_lock(void)
{
	while (__atomic_test_and_set(cache_del_pids.lock, __ATOMIC_ACQUIRE))
		CLIB_PAUSE();
}

static inline void symbol_cache_pids_unlock(void)
{
	__atomic_clear(cache_del_pids.lock, __ATOMIC_RELEASE);
}

static inline bool pid_is_already_existed(int pid)
{
	/*
	 * Make sure that there are no duplicate items of 'pid' in
	 * 'cache del pids.pid caches', so as to avoid program crashes
	 * caused by repeated release of occupied memory resources.
	 */
	struct symbolizer_cache_kvp *kv_tmp;
	vec_foreach(kv_tmp, cache_del_pids.pid_caches) {
		if ((int)kv_tmp->k.pid == pid) {
			return true;
		}
	}

	return false;
}

/*
 * When a process exits, synchronize and update its corresponding
 * symbol cache. In addition, updating the Java process symbol t-
 * able also requires calling this interface.
 *
 * @pid : The process ID (PID) that occurs when a process exits.
 */
void update_symbol_cache(pid_t pid)
{
	if (!enable_symbol_cache()) {
		return;
	}

	symbol_caches_hash_t *h = &syms_cache_hash;
	struct symbolizer_cache_kvp kv;
	kv.k.pid = (u64) pid;
	kv.v.proc_info_p = 0;
	kv.v.cache = 0;
	if (symbol_caches_hash_search(h, (symbol_caches_hash_kv *) & kv,
				      (symbol_caches_hash_kv *) & kv) == 0) {
		int ret = VEC_OK;

		symbol_cache_pids_lock();
		if (pid_is_already_existed((int)kv.k.pid)) {
			symbol_cache_pids_unlock();
			return;
		}

		vec_add1(cache_del_pids.pid_caches, kv, ret);
		if (ret != VEC_OK) {
			ebpf_warning("vec add failed.\n");
		}
		symbol_cache_pids_unlock();
	}
}

void exec_symbol_cache_update(void)
{
	symbol_caches_hash_t *h = &syms_cache_hash;
	struct symbolizer_cache_kvp *kv;
	symbol_cache_pids_lock();
	vec_foreach(kv, cache_del_pids.pid_caches) {
		free_symbolizer_cache_kvp(kv);
		if (symbol_caches_hash_add_del(h, (symbol_caches_hash_kv *) kv,
					       0 /* delete */ )) {
			ebpf_warning
			    ("symbol_caches_hash_add_del() failed.(pid %d)\n",
			     (pid_t) kv->k.pid);
		} else {
			__sync_fetch_and_add(&h->hash_elems_count, -1);
		}
	}
	vec_free(cache_del_pids.pid_caches);
	symbol_cache_pids_unlock();
}

static int init_symbol_cache(const char *name)
{
	/*
	 * Thread-safe for cache_del_pids.pids
	 */
	cache_del_pids.lock =
	    clib_mem_alloc_aligned("pids_alloc_lock",
				   CLIB_CACHE_LINE_BYTES,
				   CLIB_CACHE_LINE_BYTES, NULL);
	if (cache_del_pids.lock == NULL) {
		ebpf_error("cache_del_pids.lock alloc memory failed.\n");
		return (-1);
	}

	cache_del_pids.lock[0] = 0;
	cache_del_pids.pid_caches = NULL;

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
	kv.v.cache = 0;
	if (symbol_caches_hash_search(h, (symbol_caches_hash_kv *) & kv,
				      (symbol_caches_hash_kv *) & kv) == 0) {
		return cache_process_stime(&kv);
	}

	return 0;
}

static struct bcc_symbol_option lazy_opt = {
	.use_debug_file = false,
	.check_debug_file_crc = false,
	.lazy_symbolize = true,
	.use_symbol_type = ((1 << STT_FUNC) | (1 << STT_GNU_IFUNC)),
};

static int config_symbolizer_proc_info(struct symbolizer_proc_info *p, int pid)
{
	memset(p, 0, sizeof(*p));
	p->unknown_syms_found = false;
	p->new_java_syms_file = false;
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

	return ETR_OK;
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
	kv.v.cache = 0;
	struct symbolizer_proc_info *p = NULL;
	if (symbol_caches_hash_search(h, (symbol_caches_hash_kv *) & kv,
				      (symbol_caches_hash_kv *) & kv) != 0) {
		p = clib_mem_alloc_aligned("sym_proc_info",
					   sizeof(struct symbolizer_proc_info),
					   0, NULL);
		if (p == NULL) {
			/* exit process */
			ebpf_warning
			    ("Failed to build process information table.\n");
			return;
		}

		if (config_symbolizer_proc_info(p, pid) != ETR_OK) {
			clib_mem_free(p);
			return;
		}

		kv.v.proc_info_p = pointer_to_uword(p);
		kv.v.cache = 0;
		if (symbol_caches_hash_add_del
		    (h, (symbol_caches_hash_kv *) & kv, 1 /* is_add */ )) {
			ebpf_warning
			    ("symbol_caches_hash_add_del() failed.(pid %d)\n",
			     pid);
			free_symbolizer_cache_kvp(&kv);
			return;
		} else
			__sync_fetch_and_add(&h->hash_elems_count, 1);
	} else {
		p = (struct symbolizer_proc_info *)kv.v.proc_info_p;
		u64 curr_time = current_sys_time_secs();
		if (!p->verified) {
			if (((curr_time - (p->stime / 1000ULL)) <
			     PROC_INFO_VERIFY_TIME)) {
				goto fetch_proc_info;
			}

			/*
			 * To prevent the possibility of the process name being changed
			 * shortly after the program's initial startup, as a precaution,
			 * we will reacquire it after the program has been running stably
			 * for a period of time to avoid such situations.
			 */
			char comm[sizeof(p->comm)];
			u64 stime = (u64)
			    get_process_starttime_and_comm(pid,
							   comm,
							   sizeof(comm));
			if (stime == 0) {
				/* 
				 * Here, indicate that during the symbolization process,
				 * the process has already terminated, but the process
				 * information has not yet been cleared. In this case, we
				 * continue to use the previously retained information.
				 */
				goto fetch_proc_info;
			}

			p->stime = stime;
			memcpy(p->comm, comm, sizeof(p->comm));
			p->comm[sizeof(p->comm) - 1] = '\0';

			if (strcmp(p->comm, "java") == 0)
				p->is_java = true;
			else
				p->is_java = false;

			p->verified = true;
		}

	}

fetch_proc_info:
	copy_process_name(&kv, name);
	*stime = cache_process_stime(&kv);
	*netns_id = cache_process_netns_id(&kv);
	*ptr = p;
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
		k_resolver = (void *)bcc_symcache_new(-1, &lazy_opt);
		sys_btime_msecs = get_sys_btime_msecs();
	}

	if (pid == 0)
		return k_resolver;

	symbol_caches_hash_t *h = &syms_cache_hash;
	struct symbolizer_proc_info *p;
	struct symbolizer_cache_kvp kv;
	kv.k.pid = (u64) pid;
	kv.v.proc_info_p = 0;
	kv.v.cache = 0;
	if (symbol_caches_hash_search(h, (symbol_caches_hash_kv *) & kv,
				      (symbol_caches_hash_kv *) & kv) == 0) {
		if (!new_cache)
			return NULL;

		p = (struct symbolizer_proc_info *)kv.v.proc_info_p;
		u64 curr_time = current_sys_time_secs();
		if (p->verified) {
			/*
			 * If an unknown frame appears during the process of symbolizing
			 * the address of the Java process, we need to re-obtain the sy-
			 * mbols table of the Java process after a delay.
			 */
			if (p->is_java && p->unknown_syms_found
			    && p->update_syms_table_time == 0) {
				p->update_syms_table_time =
				    curr_time + get_java_syms_fetch_delay();
			}

			if (p->update_syms_table_time > 0
			    && curr_time >= p->update_syms_table_time) {
				/* Update java symbols table, will be executed during
				 * the next Java symbolication */
				gen_java_symbols_file(pid);
				p->new_java_syms_file = true;

				if (kv.v.cache) {
					bcc_free_symcache((void *)kv.v.cache,
							  kv.k.pid);
					kv.v.cache =
					    pointer_to_uword(bcc_symcache_new
							     ((int)kv.k.pid,
							      &lazy_opt));
					if (symbol_caches_hash_add_del
					    (h, (symbol_caches_hash_kv *) & kv,
					     1 /* is_add */ )) {
						ebpf_warning
						    ("symbol_caches_hash_add_del() failed.(pid %d)\n",
						     (int)kv.k.pid);
					}
				}

				p->unknown_syms_found = false;
				p->update_syms_table_time = 0;
			}

			if (p->is_java && (void *)kv.v.cache == NULL) {
				gen_java_symbols_file(pid);
				p->new_java_syms_file = true;
			}
		}

		if (kv.v.cache)
			return (void *)kv.v.cache;

		kv.v.cache = pointer_to_uword(bcc_symcache_new(pid, &lazy_opt));
		if (kv.v.cache > 0)
			add_symcache_count++;

		if (symbol_caches_hash_add_del
		    (h, (symbol_caches_hash_kv *) & kv, 1 /* is_add */ )) {
			ebpf_warning
			    ("symbol_caches_hash_add_del() failed.(pid %d)\n",
			     pid);
			free_symbolizer_cache_kvp(&kv);
			return NULL;
		}

		return (void *)kv.v.cache;
	}

	return NULL;
}

int create_and_init_symbolizer_caches(void)
{
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
			sym.v.cache = 0;
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

static int free_symbolizer_kvp_cb(symbol_caches_hash_kv * kv, void *ctx)
{
	struct symbolizer_cache_kvp *sym = (struct symbolizer_cache_kvp *)kv;
	free_symbolizer_cache_kvp(sym);
	(*(u64 *) ctx)++;
	return BIHASH_WALK_CONTINUE;
}

void release_symbol_caches(void)
{
	/* Update symbol_cache hash from cache_del_pids. */
	exec_symbol_cache_update();

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
}

#else /* defined AARCH64_MUSL */
/* pid : The process ID (PID) that occurs when a process exits. */
void update_symbol_cache(pid_t pid)
{
	return;
}
#endif /* AARCH64_MUSL */
