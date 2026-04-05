/*
 * Copyright (c) 2026 Yunshan Networks
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

#define _GNU_SOURCE
#include "crash_monitor.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#include "crash_symbolize.h"
#include "elf.h"
#include "log.h"
#include "utils.h"

/*
 * Crash monitor implementation overview
 * ------------------------------------
 *
 * This file focuses on the crash-capture half of the design. The goal is not
 * to keep the process alive after a fatal fault, but to preserve the original
 * failure semantics while extracting the most useful low-level machine state in
 * a way that is safe enough for signal context.
 *
 * The intended execution flow is:
 *
 *   1. During normal initialization, install fatal signal handlers and open a
 *      dedicated binary snapshot file.
 *   2. For every covered C/eBPF thread, install an alternate signal stack via
 *      sigaltstack(). This matters because the crashing thread's regular stack
 *      may itself be corrupted or exhausted.
 *   3. When a fatal signal is raised, the handler does only a minimal set of
 *      operations that are suitable for crash context:
 *         - read registers from ucontext_t,
 *         - walk the frame-pointer chain with strict bounds checks,
 *         - write a fixed-size binary snapshot with write(),
 *         - then restore default behavior and rethrow the same signal.
 *   4. A later normal-context consumer can parse the raw snapshot and perform
 *      expensive work such as symbolization, module resolution, file:line
 *      lookup, demangling, and rich log formatting.
 *
 * The code intentionally avoids placing complex work in the signal handler.
 * Operations such as malloc/free, stdio formatting, locking, ELF/DWARF
 * parsing, /proc inspection, and general logging helpers are not appropriate in
 * the fatal path because they may allocate memory, take internal locks, or
 * recurse into already-corrupted runtime state.
 */

#define CRASH_ALTSTACK_SIZE (64 * 1024)

/*
 * Process-wide and thread-local state used by the crash monitor.
 *
 * crash_snapshot_fd:
 *   File descriptor used by the fatal signal handler to append crash records.
 *   A plain descriptor is preferred because write() is one of the simplest and
 *   safest output operations available in signal context.
 *
 * crash_monitor_initialized:
 *   Guards one-time initialization of the monitor.
 *
 * crash_thread_altstack / crash_thread_prepared:
 *   Thread-local altstack bookkeeping. sigaltstack() is a per-thread property,
 *   not a process-global one, so every covered worker keeps its own state.
 *
 * crash_thread_stack_floor / crash_thread_stack_ceil:
 *   Cached bounds for the crashing thread's normal stack. The fatal handler
 *   uses these limits to keep the frame-pointer walk inside the thread's real
 *   stack instead of confusing it with the signal altstack mapping.
 *
 * crash_in_handler:
 *   A minimal recursion guard. If the handler itself faults, the code stops
 *   attempting further capture and immediately falls back to rethrowing the
 *   signal so the process still terminates correctly.
 *
 * crash_cached_modules / crash_cached_modules_count:
 *   Normal-context cache of executable file-backed mappings from /proc/self/maps.
 *   Stage 1 never rescans /proc. Instead, the handler copies this bounded cache
 *   into the on-disk record so Stage 2 can later symbolize an already-dead
 *   process using the module layout observed at crash time.
 *
 * crash_cached_executable_path:
 *   Best-effort path of /proc/self/exe, recorded alongside module metadata so
 *   Stage 2 can produce a stable crash summary even when module lookup for a
 *   specific frame fails.
 */
static int crash_snapshot_fd = -1;
static int crash_monitor_initialized;
static __thread stack_t crash_thread_altstack;
static __thread uintptr_t crash_thread_stack_floor;
static __thread uintptr_t crash_thread_stack_ceil;
static __thread int crash_thread_prepared;
static volatile sig_atomic_t crash_in_handler;
static struct crash_snapshot_module crash_cached_modules[
	CRASH_SNAPSHOT_MAX_MODULES];
static uint32_t crash_cached_modules_count;
static char crash_cached_executable_path[CRASH_SNAPSHOT_MODULE_PATH_LEN];

/*
 * Fatal signals considered interesting enough to capture. These all represent
 * conditions where the current thread can no longer be trusted to continue
 * execution safely, but where a raw register/stack snapshot is extremely useful
 * for later diagnosis.
 */
static const int fatal_signals[] = {
	SIGSEGV,
	SIGABRT,
	SIGBUS,
	SIGILL,
	SIGFPE,
};

/*
 * Return the kernel thread id (TID) of the crashing thread.
 *
 * The raw TID is often more useful than a pthread abstraction in crash output
 * because it matches /proc, perf/BPF tooling, and most operator-facing thread
 * diagnostics.
 */
static pid_t crash_gettid(void)
{
	return (pid_t)syscall(SYS_gettid);
}

/*
 * Return the fixed on-disk snapshot path.
 *
 * Crash snapshots are intentionally stored at a stable location so container
 * deployments can persist and collect them independently from the configurable
 * runtime log file path.
 */
static const char *crash_snapshot_path(void)
{
	return CRASH_SNAPSHOT_FILE;
}

static void crash_copy_bytes(void *dst, size_t dst_size, const void *src,
			    size_t src_size)
{
	size_t i;
	size_t copy_size = dst_size < src_size ? dst_size : src_size;
	uint8_t *dst_bytes = dst;
	const uint8_t *src_bytes = src;

	for (i = 0; i < copy_size; i++)
		dst_bytes[i] = src_bytes[i];
	for (; i < dst_size; i++)
		dst_bytes[i] = 0;
}

static void crash_copy_cstr(char *dst, size_t dst_size, const char *src)
{
	size_t i;

	if (dst_size == 0)
		return;
	if (src == NULL) {
		dst[0] = '\0';
		return;
	}

	for (i = 0; i + 1 < dst_size && src[i] != '\0'; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

static void crash_trim_trailing_newline(char *text)
{
	size_t len;

	if (text == NULL)
		return;
	len = strlen(text);
	while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r'))
		text[--len] = '\0';
}

static void crash_trim_deleted_suffix(char *path)
{
	static const char deleted_suffix[] = " (deleted)";
	size_t path_len;
	size_t suffix_len = sizeof(deleted_suffix) - 1;

	if (path == NULL)
		return;
	path_len = strlen(path);
	if (path_len < suffix_len)
		return;
	if (strcmp(path + path_len - suffix_len, deleted_suffix) == 0)
		path[path_len - suffix_len] = '\0';
}

static void crash_copy_module(struct crash_snapshot_module *dst,
			      const struct crash_snapshot_module *src)
{
	if (dst == NULL || src == NULL)
		return;

	dst->start = src->start;
	dst->end = src->end;
	dst->file_offset = src->file_offset;
	dst->build_id_size = src->build_id_size;
	dst->reserved = 0;
	crash_copy_bytes(dst->build_id, sizeof(dst->build_id), src->build_id,
			 sizeof(src->build_id));
	crash_copy_cstr(dst->path, sizeof(dst->path), src->path);
}

static int crash_cache_executable_path(void)
{
	ssize_t len;

	crash_cached_executable_path[0] = '\0';
	len = readlink("/proc/self/exe", crash_cached_executable_path,
		       sizeof(crash_cached_executable_path) - 1);
	if (len < 0)
		return ETR_INVAL;
	crash_cached_executable_path[len] = '\0';
	return ETR_OK;
}

static void crash_fill_module_build_id(struct crash_snapshot_module *module)
{
	uint32_t build_id_size = 0;

	module->build_id_size = 0;
	memset(module->build_id, 0, sizeof(module->build_id));
	if (elf_read_build_id(module->path, module->build_id,
			      sizeof(module->build_id),
			      &build_id_size) == ETR_OK)
		module->build_id_size = build_id_size;
}

static void crash_normalize_maps_path(char *path)
{
	char *start;

	if (path == NULL)
		return;
	crash_trim_trailing_newline(path);
	start = path;
	while (*start == ' ' || *start == '\t')
		start++;
	if (start != path)
		memmove(path, start, strlen(start) + 1);
	crash_trim_deleted_suffix(path);
}

static int crash_cache_modules(void)
{
	FILE *maps;
	char line[4096];

	/*
	 * Build a bounded cache of executable mappings in normal context.
	 *
	 * This is the bridge between the two crash-monitor stages:
	 *   - Stage 1 cannot safely rescan /proc/self/maps while the process is
	 *     already crashing.
	 *   - Stage 2 still needs enough metadata to translate raw PCs into
	 *     module-relative offsets after the original process image is gone.
	 *
	 * The compromise is to snapshot a small, fixed-size subset of the current
	 * process layout up front. The fatal handler later copies these entries into
	 * the binary crash record without doing any additional discovery work.
	 */
	crash_cached_modules_count = 0;
	memset(crash_cached_modules, 0, sizeof(crash_cached_modules));
	(void)crash_cache_executable_path();

	maps = fopen("/proc/self/maps", "r");
	if (maps == NULL)
		return ETR_INVAL;

	while (fgets(line, sizeof(line), maps) != NULL) {
		unsigned long long start;
		unsigned long long end;
		unsigned long long offset;
		unsigned long inode;
		char perms[5] = { 0 };
		char dev[32] = { 0 };
		char path[CRASH_SNAPSHOT_MODULE_PATH_LEN] = { 0 };
		struct crash_snapshot_module *module;
		int fields;

		if (crash_cached_modules_count >= CRASH_SNAPSHOT_MAX_MODULES)
			break;

		fields = sscanf(line, "%llx-%llx %4s %llx %31s %lu %255[^\n]",
			       &start, &end, perms, &offset, dev, &inode, path);
		if (fields < 7)
			continue;
		if (strchr(perms, 'x') == NULL)
			continue;
		crash_normalize_maps_path(path);
		if (path[0] != '/')
			continue;

		module = &crash_cached_modules[crash_cached_modules_count];
		module->start = start;
		module->end = end;
		module->file_offset = offset;
		module->reserved = 0;
		crash_copy_cstr(module->path, sizeof(module->path), path);
		crash_fill_module_build_id(module);
		crash_cached_modules_count++;
	}

	fclose(maps);
	if (crash_cached_executable_path[0] == '\0' &&
	    crash_cached_modules_count > 0)
		crash_copy_cstr(crash_cached_executable_path,
				sizeof(crash_cached_executable_path),
				crash_cached_modules[0].path);
	return ETR_OK;
}

static void crash_copy_cached_modules_to_record(struct crash_snapshot_record *record)
{
	uint32_t i;

	if (record == NULL)
		return;

	/*
	 * Copy the precomputed module cache into the fixed-size record before the
	 * handler touches frame data. Keeping this as a simple bounded memcpy-style
	 * operation avoids any need for dynamic discovery in signal context while
	 * preserving enough information for later module and build-id based lookup.
	 */
	record->modules_count = crash_cached_modules_count;
	crash_copy_cstr(record->executable_path, sizeof(record->executable_path),
			crash_cached_executable_path);
	for (i = 0; i < crash_cached_modules_count; i++)
		crash_copy_module(&record->modules[i], &crash_cached_modules[i]);
}

static void crash_fill_frame_module(struct crash_snapshot_record *record,
				    struct crash_snapshot_frame *frame)
{
	uint32_t i;

	if (record == NULL || frame == NULL)
		return;

	/*
	 * Convert an absolute runtime PC into the ASLR-stable tuple consumed by
	 * Stage 2: (module_index, rel_pc).
	 *
	 * The absolute PC is still kept as the ground-truth fallback value, but a
	 * later process can only symbolize reliably if it also knows which module
	 * owned the address and what the module-relative offset was at crash time.
	 */
	frame->module_index = CRASH_SNAPSHOT_INVALID_MODULE;
	frame->rel_pc = 0;
	for (i = 0; i < record->modules_count; i++) {
		const struct crash_snapshot_module *module = &record->modules[i];

		if (frame->absolute_pc < module->start ||
		    frame->absolute_pc >= module->end)
			continue;
		frame->module_index = i;
		frame->rel_pc = frame->absolute_pc - module->start;
		break;
	}
}

static void crash_fill_record_frame_modules(struct crash_snapshot_record *record)
{
	uint32_t i;
	uint32_t frames;

	if (record == NULL)
		return;

	/*
	 * The top frame may be appended directly from the interrupted IP and the
	 * rest may come from a best-effort frame-pointer walk. Annotate every stored
	 * frame afterwards so both capture paths share the same module lookup logic.
	 */
	frames = record->frames_count;
	if (frames > CRASH_SNAPSHOT_MAX_FRAMES)
		frames = CRASH_SNAPSHOT_MAX_FRAMES;
	for (i = 0; i < frames; i++)
		crash_fill_frame_module(record, &record->frames[i]);
}

/*
 * Open the binary snapshot stream used by the fatal signal handler.
 *
 * The file is opened in normal context and kept open for the lifetime of the
 * process. The signal handler later reuses only the descriptor and appends a
 * single fixed-size record with write().
 */
static int crash_open_snapshot_file(void)
{
	return open(crash_snapshot_path(), O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC,
		    0640);
}

/*
 * Store one program counter into the fixed-size frame array.
 *
 * Stage 1 now preserves both the absolute runtime PC and, when a cached module
 * match is available, the module-relative offset plus module index needed by
 * Stage 2 symbolization.
 */
static void crash_fill_frame(struct crash_snapshot_record *record,
			     struct crash_snapshot_frame *frame,
			     uint64_t absolute_pc)
{
	frame->absolute_pc = absolute_pc;
	frame->rel_pc = 0;
	frame->module_index = CRASH_SNAPSHOT_INVALID_MODULE;
	frame->reserved = 0;
	if (record != NULL)
		crash_fill_frame_module(record, frame);
}

static int crash_append_frame(struct crash_snapshot_record *record,
			      uint64_t absolute_pc)
{
	if (absolute_pc == 0 || record->frames_count >= CRASH_SNAPSHOT_MAX_FRAMES)
		return 0;

	crash_fill_frame(record, &record->frames[record->frames_count], absolute_pc);
	record->frames_count++;
	return 1;
}

static void crash_cache_thread_stack_bounds(void)
{
	pthread_attr_t attr;
	void *stack_addr = NULL;
	size_t stack_size = 0;

	crash_thread_stack_floor = 0;
	crash_thread_stack_ceil = 0;

	if (pthread_getattr_np(pthread_self(), &attr) != 0)
		return;
	if (pthread_attr_getstack(&attr, &stack_addr, &stack_size) == 0 &&
	    stack_addr != NULL && stack_size != 0) {
		crash_thread_stack_floor = (uintptr_t)stack_addr;
		crash_thread_stack_ceil = crash_thread_stack_floor + stack_size;
	}
	(void)pthread_attr_destroy(&attr);
}

/*
 * Install an alternate signal stack for the current thread.
 *
 * This is a critical part of the design: if the thread crashes because of stack
 * overflow, stack corruption, or a frame-pointer chain that points into broken
 * stack memory, handling the signal on the regular stack may fail immediately.
 * By moving the signal handler onto a dedicated mapping, the crash monitor has
 * a much better chance of recording a snapshot before the process terminates.
 *
 * The function first checks whether a suitable altstack already exists. If not,
 * it allocates a fresh mapping and registers it with sigaltstack(). The mapping
 * is intentionally retained for the lifetime of the thread.
 */
static int crash_install_altstack(void)
{
	stack_t current;
	void *altstack_mem;

	if (crash_thread_prepared)
		return ETR_OK;

	crash_cache_thread_stack_bounds();
	memset(&current, 0, sizeof(current));
	if (sigaltstack(NULL, &current) == 0 &&
	    !(current.ss_flags & SS_DISABLE) && current.ss_sp != NULL &&
	    current.ss_size >= CRASH_ALTSTACK_SIZE) {
		crash_thread_prepared = 1;
		return ETR_OK;
	}

	altstack_mem = mmap(NULL, CRASH_ALTSTACK_SIZE, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (altstack_mem == MAP_FAILED)
		return ETR_INVAL;

	memset(&crash_thread_altstack, 0, sizeof(crash_thread_altstack));
	crash_thread_altstack.ss_sp = altstack_mem;
	crash_thread_altstack.ss_size = CRASH_ALTSTACK_SIZE;

	stack_t ss = {
		.ss_sp = crash_thread_altstack.ss_sp,
		.ss_size = crash_thread_altstack.ss_size,
		.ss_flags = 0,
	};
	if (sigaltstack(&ss, NULL) != 0) {
		munmap(altstack_mem, CRASH_ALTSTACK_SIZE);
		memset(&crash_thread_altstack, 0, sizeof(crash_thread_altstack));
		return ETR_INVAL;
	}

	crash_thread_prepared = 1;
	return ETR_OK;
}

/*
 * Validate one frame-pointer transition before following it.
 *
 * The manual unwind path must stay conservative. Rather than trying to salvage
 * obviously bad stack state, the code stops as soon as the next frame pointer
 * looks suspicious:
 *   - it must move forward monotonically,
 *   - it must remain naturally aligned,
 *   - and it must stay inside the known signal-stack bounds when those bounds
 *     are available.
 *
 * This greatly reduces the chance that crash processing itself will fault while
 * reading corrupted stack memory.
 */
static int crash_is_frame_pointer_valid(uintptr_t current_fp, uintptr_t next_fp,
					uintptr_t stack_floor,
					uintptr_t stack_ceil)
{
	if (next_fp <= current_fp)
		return 0;
	if ((next_fp & (sizeof(uintptr_t) - 1)) != 0)
		return 0;
	if (stack_floor != 0 && next_fp < stack_floor)
		return 0;
	if (stack_ceil != 0 && next_fp + sizeof(uintptr_t) * 2 > stack_ceil)
		return 0;
	return 1;
}

/*
 * Perform a bounded frame-pointer walk and collect return addresses.
 *
 * This is intentionally much simpler than a general-purpose DWARF unwinder.
 * In a fatal signal handler we want the minimum amount of logic needed to get a
 * useful backtrace candidate. The algorithm assumes frame pointers are present
 * and repeatedly reads:
 *   frame[0] -> next frame pointer
 *   frame[1] -> saved return address
 *
 * Collection stops when a null return address is observed, the next frame looks
 * invalid, or the caller-provided output array is full.
 */
static uint32_t crash_collect_frames(struct crash_snapshot_frame *frames,
				     uint32_t max_frames,
				     uintptr_t fp,
				     uintptr_t stack_floor,
				     uintptr_t stack_ceil)
{
	uint32_t count = 0;
	uintptr_t current_fp = fp;

	while (current_fp != 0 && count < max_frames) {
		uintptr_t *frame;
		uintptr_t next_fp;
		uintptr_t return_addr;

		if ((current_fp & (sizeof(uintptr_t) - 1)) != 0)
			break;
		if (stack_floor != 0 && current_fp < stack_floor)
			break;
		if (stack_ceil != 0 &&
		    current_fp + sizeof(uintptr_t) * 2 > stack_ceil)
			break;

		frame = (uintptr_t *)current_fp;
		next_fp = frame[0];
		return_addr = frame[1];
		if (return_addr == 0)
			break;
		crash_fill_frame(NULL, &frames[count++], (uint64_t)return_addr);
		if (!crash_is_frame_pointer_valid(current_fp, next_fp, stack_floor,
						 stack_ceil))
			break;
		current_fp = next_fp;
	}

	return count;
}

/*
 * Copy crash-time machine context out of ucontext_t.
 *
 * ucontext_t is the kernel-provided register state of the interrupted frame.
 * This function turns that machine context into the stable snapshot fields used
 * by later consumers:
 *   - architecture id,
 *   - top-frame control registers (IP/SP/FP/LR),
 *   - a best-effort set of ABI argument registers,
 *   - and a bounded stack trace candidate built from the frame pointer.
 *
 * The argument capture is intentionally limited to the crashing frame's raw ABI
 * register values. It does not promise source-level reconstruction of stacked,
 * floating-point, optimized-out, or non-top-frame arguments.
 */
static void crash_fill_record_from_ucontext(struct crash_snapshot_record *record,
					    ucontext_t *ctx)
{
	uintptr_t stack_floor = crash_thread_stack_floor;
	uintptr_t stack_ceil = crash_thread_stack_ceil;

	if (record == NULL || ctx == NULL)
		return;

	/*
	 * uc_stack describes the thread's registered signal altstack state, not the
	 * normal stack that the interrupted frame pointer walks through. Cache the
	 * thread's ordinary stack bounds during normal context setup and use them
	 * here so the fatal-path unwind remains conservative without accidentally
	 * constraining itself to the altstack mapping.
	 */

#if defined(__x86_64__)
	record->arch = CRASH_SNAPSHOT_ARCH_X86_64;
	record->ip = (uint64_t)ctx->uc_mcontext.gregs[REG_RIP];
	record->sp = (uint64_t)ctx->uc_mcontext.gregs[REG_RSP];
	record->fp = (uint64_t)ctx->uc_mcontext.gregs[REG_RBP];
	record->lr = 0;
	record->args[0] = (uint64_t)ctx->uc_mcontext.gregs[REG_RDI];
	record->args[1] = (uint64_t)ctx->uc_mcontext.gregs[REG_RSI];
	record->args[2] = (uint64_t)ctx->uc_mcontext.gregs[REG_RDX];
	record->args[3] = (uint64_t)ctx->uc_mcontext.gregs[REG_RCX];
	record->args[4] = (uint64_t)ctx->uc_mcontext.gregs[REG_R8];
	record->args[5] = (uint64_t)ctx->uc_mcontext.gregs[REG_R9];
	(void)crash_append_frame(record, record->ip);
	record->frames_count +=
		crash_collect_frames(record->frames + record->frames_count,
				     CRASH_SNAPSHOT_MAX_FRAMES -
				     record->frames_count,
				     (uintptr_t)record->fp, stack_floor,
				     stack_ceil);
#elif defined(__aarch64__)
	record->arch = CRASH_SNAPSHOT_ARCH_AARCH64;
	record->ip = (uint64_t)ctx->uc_mcontext.pc;
	record->sp = (uint64_t)ctx->uc_mcontext.sp;
	record->fp = (uint64_t)ctx->uc_mcontext.regs[29];
	record->lr = (uint64_t)ctx->uc_mcontext.regs[30];
	record->args[0] = (uint64_t)ctx->uc_mcontext.regs[0];
	record->args[1] = (uint64_t)ctx->uc_mcontext.regs[1];
	record->args[2] = (uint64_t)ctx->uc_mcontext.regs[2];
	record->args[3] = (uint64_t)ctx->uc_mcontext.regs[3];
	record->args[4] = (uint64_t)ctx->uc_mcontext.regs[4];
	record->args[5] = (uint64_t)ctx->uc_mcontext.regs[5];
	record->args[6] = (uint64_t)ctx->uc_mcontext.regs[6];
	record->args[7] = (uint64_t)ctx->uc_mcontext.regs[7];
	(void)crash_append_frame(record, record->ip);
	/*
	 * On AArch64 the link register often contains a useful caller hint even when
	 * the full frame walk is short. Record it as an extra top-level clue before
	 * continuing along the frame-pointer chain.
	 */
	(void)crash_append_frame(record, record->lr);
	record->frames_count +=
		crash_collect_frames(record->frames + record->frames_count,
				     CRASH_SNAPSHOT_MAX_FRAMES -
				     record->frames_count,
				     (uintptr_t)record->fp, stack_floor,
				     stack_ceil);
#else
	record->arch = CRASH_SNAPSHOT_ARCH_UNKNOWN;
#endif
}

/*
 * Re-deliver the original fatal signal after snapshot capture.
 *
 * The crash monitor is diagnostic-only. It must not swallow the crash or allow
 * the process to continue in an undefined state. By restoring SIG_DFL and then
 * sending the same signal to the process, we preserve the expected exit status
 * and leave room for the platform's normal crash handling behavior.
 */
static void crash_rethrow_signal(int signo)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = SIG_DFL;
	sigemptyset(&action.sa_mask);
	sigaction(signo, &action, NULL);
	kill(getpid(), signo);
	_exit(128 + signo);
}

/*
 * Fatal signal handler.
 *
 * This function embodies the core crash-capture policy:
 *   - avoid recursion,
 *   - build a fixed-size binary record on the stack,
 *   - fill it from kernel-supplied crash state,
 *   - append it with write(),
 *   - and immediately restore the original crash behavior.
 *
 * Important design rule: this is intentionally not the place for symbolization,
 * pretty formatting, dynamic allocation, or normal logging helpers. The handler
 * is expected to do the minimum possible work needed to preserve evidence.
 *
 * The complementary Stage-2 path lives in crash_monitor_consume_pending_snapshots().
 * That function runs later during normal startup, after the process has a clean
 * runtime again. Keeping the two stages separate avoids pulling file scanning,
 * record validation, rich logging, truncation of consumed snapshots, or future
 * symbolization work into the crashing thread's async-signal context.
 */
static void crash_signal_handler(int signo, siginfo_t *info, void *ucontext)
{
	struct crash_snapshot_record record;
	ucontext_t *ctx = (ucontext_t *)ucontext;
	ssize_t unused;

	if (crash_in_handler)
		crash_rethrow_signal(signo);
	crash_in_handler = 1;

	memset(&record, 0, sizeof(record));
	record.magic = CRASH_SNAPSHOT_MAGIC;
	record.version = CRASH_SNAPSHOT_VERSION;
	record.size = sizeof(record);
	record.signal = (uint32_t)signo;
	record.si_code = info ? info->si_code : 0;
	record.pid = (uint32_t)getpid();
	record.tid = (uint32_t)crash_gettid();
	record.fault_addr = (uint64_t)(uintptr_t)(info ? info->si_addr : NULL);
	/*
	 * Preserve the normal-context module snapshot before collecting frames. This
	 * keeps the fatal path free of /proc parsing while still giving Stage 2 the
	 * exact module ranges, file offsets, and build-ids that were observed in the
	 * crashing process.
	 */
	crash_copy_cached_modules_to_record(&record);
	crash_fill_record_from_ucontext(&record, ctx);
	/*
	 * Re-run frame annotation after register and stack capture so every collected
	 * absolute PC carries its best-effort module-relative representation.
	 */
	crash_fill_record_frame_modules(&record);

	if (crash_snapshot_fd >= 0) {
		unused = write(crash_snapshot_fd, &record, sizeof(record));
		(void)unused;
	}

	crash_rethrow_signal(signo);
}

/*
 * Register crash handlers for all fatal signals of interest.
 *
 * SA_SIGINFO allows the handler to receive both siginfo_t and ucontext_t.
 * SA_ONSTACK forces execution on the alternate signal stack prepared for the
 * thread. SA_RESETHAND ensures that after the first fatal delivery, the signal
 * disposition returns to the default action.
 */
static int crash_install_signal_handlers(void)
{
	struct sigaction action;
	size_t i;

	memset(&action, 0, sizeof(action));
	action.sa_sigaction = crash_signal_handler;
	action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
	sigfillset(&action.sa_mask);

	for (i = 0; i < sizeof(fatal_signals) / sizeof(fatal_signals[0]); i++) {
		if (sigaction(fatal_signals[i], &action, NULL) != 0)
			return ETR_INVAL;
	}

	return ETR_OK;
}

static void crash_log_pending_record(const struct crash_snapshot_record *record)
{
	if (record == NULL)
		return;
	/*
	 * Stage 2 is deliberately best-effort. A single frame may fail module,
	 * symbol, or line lookup, but the consumer should still emit the recovered
	 * summary and whatever raw per-frame data remains available.
	 */
	(void)crash_symbolize_record(record);
}

/*
 * Consume any pending snapshots left by a previous crash.
 *
 * This runs in normal process context, so it is allowed to use the standard log
 * helpers. Pending records are validated, symbolized on a best-effort basis,
 * and then cleared from the snapshot file so later startups do not re-emit the
 * same crash.
 *
 * This function is intentionally separate from the fatal signal handler. The
 * handler's job is only to preserve evidence with a tiny async-signal-safe
 * sequence: collect registers, perform a bounded frame walk, append one fixed
 * record with write(), and rethrow the original signal. Consuming historical
 * snapshot files requires a wider and less predictable set of actions such as
 * reading the whole file, validating each record, logging formatted output, and
 * truncating already-consumed data. Those operations are appropriate only after
 * the process has returned to a clean normal-context startup path.
 */
int crash_monitor_consume_pending_snapshots(void)
{
	const char *path = crash_snapshot_path();
	struct crash_snapshot_record record;
	int fd;
	ssize_t nread;

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			return ETR_OK;
		return ETR_INVAL;
	}

	while ((nread = read(fd, &record, sizeof(record))) == sizeof(record)) {
		if (record.magic != CRASH_SNAPSHOT_MAGIC ||
		    record.version != CRASH_SNAPSHOT_VERSION ||
		    record.size != sizeof(record)) {
			ebpf_warning("Discard invalid crash snapshot record from %s\n",
				     path);
			continue;
		}
		crash_log_pending_record(&record);
	}

	if (nread < 0) {
		close(fd);
		return ETR_INVAL;
	}
	if (nread != 0)
		ebpf_warning("Discard truncated crash snapshot file %s\n", path);
	if (ftruncate(fd, 0) != 0) {
		close(fd);
		return ETR_INVAL;
	}

	close(fd);
	return ETR_OK;
}

/*
 * Prepare the current thread for crash capture.
 *
 * Because sigaltstack() is per-thread, this function is expected to be called
 * from every covered worker thread before normal work begins. If process-wide
 * crash monitoring has not been initialized yet, the call becomes a no-op.
 */
int crash_monitor_prepare_thread(void)
{
	if (!crash_monitor_initialized)
		return ETR_OK;
	return crash_install_altstack();
}

/*
 * Initialize process-wide crash capture state.
 *
 * This routine is responsible for creating the snapshot file, performing the
 * first thread's altstack preparation, and installing fatal signal handlers.
 * Later calls from additional threads reuse the existing global state and only
 * prepare the calling thread's altstack.
 */
int crash_monitor_init(void)
{
	if (crash_monitor_initialized)
		return crash_monitor_prepare_thread();

	crash_snapshot_fd = crash_open_snapshot_file();
	if (crash_snapshot_fd < 0)
		return ETR_INVAL;
	if (crash_cache_modules() != ETR_OK)
		goto err;

	crash_monitor_initialized = 1;
	if (crash_monitor_prepare_thread() != ETR_OK)
		goto err;
	if (crash_install_signal_handlers() != ETR_OK)
		goto err;

	return ETR_OK;

err:
	crash_monitor_initialized = 0;
	close(crash_snapshot_fd);
	crash_snapshot_fd = -1;
	return ETR_INVAL;
}
