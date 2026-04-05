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

#ifndef DF_USER_CRASH_MONITOR_H
#define DF_USER_CRASH_MONITOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Crash snapshot ABI overview
 * ---------------------------
 *
 * The crash monitor is intentionally designed as a two-stage mechanism:
 *
 *   Stage 1 (fatal signal context)
 *     - Run from a SIGSEGV/SIGABRT/SIGBUS/... handler.
 *     - Capture only raw machine state that can be gathered safely.
 *     - Avoid malloc/free, stdio formatting, pthread locks, libelf/libdwarf,
 *       /proc parsing, or any other operation that may deadlock or recurse
 *       while the process is already crashing.
 *     - Append a fixed-size binary record with write().
 *
 *   Stage 2 (normal context)
 *     - Read the binary snapshot file later, when it is safe to allocate
 *       memory, take locks, parse ELF/DWARF, or emit rich logs.
 *     - Resolve modules, symbols, and file:line information from the raw
 *       addresses captured in Stage 1.
 *
 * The data structures below form the on-disk contract between those two
 * stages. They are versioned and fixed-size on purpose so that the signal
 * handler can simply zero-fill a record, populate bounded fields, and write
 * the whole structure without building variable-length text buffers.
 */
#define CRASH_SNAPSHOT_MAGIC 0x44464352U
#define CRASH_SNAPSHOT_VERSION 2
#define CRASH_SNAPSHOT_MAX_FRAMES 32
#define CRASH_SNAPSHOT_ARG_REGS 8
#define CRASH_SNAPSHOT_MAX_MODULES 32
#define CRASH_SNAPSHOT_MODULE_PATH_LEN 256
#define CRASH_SNAPSHOT_BUILD_ID_SIZE 20
#define CRASH_SNAPSHOT_INVALID_MODULE 0xffffffffU
#define CRASH_SNAPSHOT_FILE "/var/log/deepflow-agent/deepflow-agent.crash"

enum crash_snapshot_arch {
	CRASH_SNAPSHOT_ARCH_UNKNOWN = 0,
	CRASH_SNAPSHOT_ARCH_X86_64 = 1,
	CRASH_SNAPSHOT_ARCH_AARCH64 = 2,
};

/*
 * Metadata for one executable mapping that may own one or more collected PCs.
 *
 * start/end:
 *   Runtime virtual address range as observed in the crashing process.
 *
 * file_offset:
 *   File offset corresponding to the beginning of the mapped range. Combined
 *   with absolute_pc, this lets a later consumer reconstruct a file-relative PC
 *   that is stable across ASLR.
 *
 * build_id:
 *   Optional GNU build-id bytes (when available). This allows a normal-context
 *   symbolizer to match the crashed image with external debuginfo more
 *   accurately than by pathname alone.
 *
 * path:
 *   Best-effort path of the mapped binary or shared object.
 */
struct crash_snapshot_module {
	uint64_t start;
	uint64_t end;
	uint64_t file_offset;
	uint32_t build_id_size;
	uint32_t reserved;
	uint8_t build_id[CRASH_SNAPSHOT_BUILD_ID_SIZE];
	char path[CRASH_SNAPSHOT_MODULE_PATH_LEN];
};

/*
 * One captured stack frame.
 *
 * absolute_pc:
 *   The exact runtime instruction pointer captured at crash time.
 *
 * rel_pc + module_index:
 *   Optional ASLR-stable representation of the same frame. If the producer can
 *   identify the owning module, rel_pc stores the module-relative offset and
 *   module_index points into the modules[] array. Consumers should be prepared
 *   for module_index == CRASH_SNAPSHOT_INVALID_MODULE when module lookup was
 *   unavailable or intentionally skipped in signal context.
 */
struct crash_snapshot_frame {
	uint64_t absolute_pc;
	uint64_t rel_pc;
	uint32_t module_index;
	uint32_t reserved;
};

/*
 * Fixed-size crash record appended directly from the fatal signal handler.
 *
 * magic/version/size:
 *   Basic sanity checks for readers. A consumer can reject truncated or stale
 *   records before interpreting the payload.
 *
 * signal/si_code/fault_addr:
 *   Original crash reason provided by the kernel.
 *
 * ip/sp/fp/lr:
 *   Top-frame register snapshot, copied straight from ucontext_t.
 *
 * args[]:
 *   Best-effort ABI argument registers for the crashing frame only. These are
 *   raw integer/pointer register values, not reconstructed high-level source
 *   language arguments. Stack-passed, floating-point, optimized-out, or older
 *   frame arguments are outside the guarantees of this snapshot format.
 *
 * modules[] / frames[]:
 *   Bounded arrays reserved so the signal handler never has to allocate memory
 *   while collecting stack state. modules_count and frames_count indicate how
 *   many entries were actually populated.
 */
struct crash_snapshot_record {
	uint32_t magic;
	uint16_t version;
	uint16_t arch;
	uint32_t size;
	uint32_t signal;
	int32_t si_code;
	uint32_t pid;
	uint32_t tid;
	uint64_t fault_addr;
	uint64_t ip;
	uint64_t sp;
	uint64_t fp;
	uint64_t lr;
	uint64_t args[CRASH_SNAPSHOT_ARG_REGS];
	char executable_path[CRASH_SNAPSHOT_MODULE_PATH_LEN];
	uint32_t modules_count;
	uint32_t frames_count;
	struct crash_snapshot_module modules[CRASH_SNAPSHOT_MAX_MODULES];
	struct crash_snapshot_frame frames[CRASH_SNAPSHOT_MAX_FRAMES];
};

/*
 * Initializes crash capture for the current process.
 *
 * This call is expected to:
 *   - open or create the dedicated snapshot file,
 *   - install fatal signal handlers,
 *   - and prepare the calling thread's alternate signal stack.
 *
 * The snapshot path is fixed at CRASH_SNAPSHOT_FILE so crash persistence does
 * not depend on the configured runtime log path.
 */
int crash_monitor_init(void);

/*
 * Installs per-thread signal altstack support.
 *
 * Important: sigaltstack() is thread-local, not process-global. Every covered
 * C/eBPF worker thread must call this before doing normal work, otherwise a
 * stack corruption bug could prevent the fatal signal handler from running on a
 * valid stack.
 */
int crash_monitor_prepare_thread(void);

/*
 * Stage-2 consumer entry point.
 *
 * The implementation is expected to parse any pending binary crash snapshots in
 * normal context, resolve module/symbol/file:line information, and emit the
 * final human-readable crash report. Because this runs outside signal context,
 * it may safely use allocators, locks, /proc parsing, ELF/DWARF libraries, and
 * richer logging facilities.
 *
 * This split is intentional. The fatal signal handler should capture evidence
 * with the smallest possible async-signal-safe surface area and then rethrow
 * the original signal. Reading old snapshot files, validating multiple records,
 * formatting logs, truncating consumed state, and future symbolization work all
 * belong to normal process context, not to the crashing thread's handler.
 *
 * The snapshot file location is fixed at CRASH_SNAPSHOT_FILE.
 */
int crash_monitor_consume_pending_snapshots(void);

#ifdef __cplusplus
}
#endif

#endif /* DF_USER_CRASH_MONITOR_H */
