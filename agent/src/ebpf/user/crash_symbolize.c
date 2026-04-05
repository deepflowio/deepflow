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

#include "crash_symbolize.h"

#include <fcntl.h>
#include <inttypes.h>
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "elf.h"
#include "log.h"
#include "utils.h"

#define CRASH_SYMBOL_NAME_LEN 256

/*
 * Stage-2 symbolization overview
 * ------------------------------
 *
 * The fatal signal handler stores only raw, bounded crash data in the on-disk
 * snapshot. This file is the normal-context counterpart that turns that raw
 * data into something operators can read:
 *
 *   - map each frame back to the module captured at crash time,
 *   - prefer external debuginfo matched by build-id when available,
 *   - translate file-relative PCs into ELF virtual addresses,
 *   - recover function names from ELF and/or DWARF metadata,
 *   - recover source file and line information from DWARF line tables,
 *   - and fall back to raw addresses whenever any step fails.
 *
 * Best-effort behavior is deliberate. A missing module, stripped symbol table,
 * absent debuginfo package, or incomplete DWARF section should degrade the log
 * for that frame only; it should not prevent the rest of the recovered crash
 * record from being emitted.
 */

/*
 * Per-frame working state built while symbolizing one snapshot frame.
 *
 * The struct keeps both the raw reconstruction inputs (module, file_offset_pc)
 * and the progressively richer outputs (ELF vaddr, symbol, file:line). The
 * boolean flags make it explicit which stages succeeded so the logging layer
 * can print the richest available representation without assuming every lookup
 * completed.
 */
struct crash_symbolized_frame {
	const struct crash_snapshot_module *module;
	uint64_t file_offset_pc;
	uint64_t elf_vaddr;
	char symbol_name[CRASH_SYMBOL_NAME_LEN];
	uint64_t symbol_addr;
	uint64_t symbol_size;
	char file_path[CRASH_SNAPSHOT_MODULE_PATH_LEN];
	uint64_t line;
	bool has_module;
	bool has_elf_vaddr;
	bool has_symbol;
	bool has_line;
};

/*
 * Convert the in-record binary build-id bytes into a printable lowercase hex
 * string. Logging and debuginfo path generation both use this representation.
 */
static void crash_format_build_id(const struct crash_snapshot_module *module,
				 char *buf, size_t buf_size)
{
	static const char hex[] = "0123456789abcdef";
	size_t i;
	size_t limit;

	if (buf == NULL || buf_size == 0)
		return;
	buf[0] = '\0';
	if (module == NULL || module->build_id_size == 0)
		return;

	limit = module->build_id_size;
	if (limit > sizeof(module->build_id))
		limit = sizeof(module->build_id);
	if (limit > (buf_size - 1) / 2)
		limit = (buf_size - 1) / 2;
	for (i = 0; i < limit; i++) {
		buf[i * 2] = hex[module->build_id[i] >> 4];
		buf[i * 2 + 1] = hex[module->build_id[i] & 0xf];
	}
	buf[limit * 2] = '\0';
}

/*
 * Copy a C string into a bounded destination buffer and always NUL-terminate.
 * Stage 2 is normal-context code, but it still keeps the snapshot-facing data
 * structures fixed-size and truncation-safe.
 */
static void crash_copy_cstr(char *dst, size_t dst_size, const char *src)
{
	size_t i;

	if (dst == NULL || dst_size == 0)
		return;
	if (src == NULL) {
		dst[0] = '\0';
		return;
	}
	for (i = 0; i + 1 < dst_size && src[i] != '\0'; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

/*
 * Persist the chosen symbol name inside result-owned storage.
 *
 * The underlying libelf/libdwarf string may become invalid after the ELF/DWARF
 * objects are torn down, so Stage 2 copies the selected name into a fixed local
 * buffer before any cleanup happens.
 */
static void crash_set_symbol_name(struct crash_symbolized_frame *result,
				  const char *name, uint64_t symbol_addr,
				  uint64_t symbol_size)
{
	if (result == NULL || name == NULL || name[0] == '\0')
		return;

	crash_copy_cstr(result->symbol_name, sizeof(result->symbol_name), name);
	result->symbol_addr = symbol_addr;
	result->symbol_size = symbol_size;
	result->has_symbol = true;
}

/*
 * Resolve the frame's recorded module_index back to the module metadata that
 * Stage 1 copied into the snapshot record. If Stage 1 could not identify the
 * module, symbolization falls back to raw-PC logging for that frame.
 */
static int crash_find_module(const struct crash_snapshot_record *record,
			    const struct crash_snapshot_frame *frame,
			    const struct crash_snapshot_module **module)
{
	if (module != NULL)
		*module = NULL;
	if (record == NULL || frame == NULL || module == NULL)
		return ETR_INVAL;
	if (frame->module_index == CRASH_SNAPSHOT_INVALID_MODULE ||
	    frame->module_index >= record->modules_count ||
	    frame->module_index >= CRASH_SNAPSHOT_MAX_MODULES)
		return ETR_NOTEXIST;
	*module = &record->modules[frame->module_index];
	return ETR_OK;
}

/*
 * Verify that a candidate external debuginfo file matches the build-id captured
 * from the crashing process. Path-based lookup is convenient, but build-id
 * matching is what keeps symbolization tied to the exact image revision.
 */
static int crash_debug_file_matches_build_id(
		const struct crash_snapshot_module *module, const char *path)
{
	uint8_t build_id[CRASH_SNAPSHOT_BUILD_ID_SIZE];
	uint32_t build_id_size = 0;

	if (module == NULL || path == NULL)
		return 0;
	if (module->build_id_size == 0)
		return 1;
	if (elf_read_build_id(path, build_id, sizeof(build_id), &build_id_size) !=
	    ETR_OK)
		return 1;
	if (build_id_size != module->build_id_size)
		return 0;
	return memcmp(build_id, module->build_id, build_id_size) == 0;
}

/*
 * Look for split debuginfo in the standard build-id hierarchy used by many
 * distros: /usr/lib/debug/.build-id/xx/yyyy....debug.
 */
static int crash_find_build_id_debug_image(
		const struct crash_snapshot_module *module, char *path,
		size_t path_size)
{
	char build_id[CRASH_SNAPSHOT_BUILD_ID_SIZE * 2 + 1];
	int len;

	if (path != NULL && path_size > 0)
		path[0] = '\0';
	if (module == NULL || path == NULL || path_size == 0 ||
	    module->build_id_size <= 1)
		return ETR_NOTEXIST;

	crash_format_build_id(module, build_id, sizeof(build_id));
	if (build_id[0] == '\0' || build_id[1] == '\0' || build_id[2] == '\0')
		return ETR_NOTEXIST;

	len = snprintf(path, path_size, "/usr/lib/debug/.build-id/%c%c/%s.debug",
		       build_id[0], build_id[1], build_id + 2);
	if (len < 0 || (size_t)len >= path_size)
		return ETR_NOTEXIST;
	if (access(path, R_OK) != 0)
		return ETR_NOTEXIST;
	if (!crash_debug_file_matches_build_id(module, path))
		return ETR_NOTEXIST;
	return ETR_OK;
}

/*
 * Fall back to the common pathname-based split-debuginfo location when the
 * build-id hierarchy is unavailable.
 */
static int crash_find_path_debug_image(const struct crash_snapshot_module *module,
				      char *path, size_t path_size)
{
	int len;

	if (path != NULL && path_size > 0)
		path[0] = '\0';
	if (module == NULL || path == NULL || path_size == 0 ||
	    module->path[0] != '/')
		return ETR_NOTEXIST;

	len = snprintf(path, path_size, "/usr/lib/debug%s.debug", module->path);
	if (len < 0 || (size_t)len >= path_size)
		return ETR_NOTEXIST;
	if (access(path, R_OK) != 0)
		return ETR_NOTEXIST;
	if (!crash_debug_file_matches_build_id(module, path))
		return ETR_NOTEXIST;
	return ETR_OK;
}

/*
 * Choose the best debuginfo image available for a module. The preference order
 * is intentionally strict: build-id match first, then pathname-based fallback.
 */
static int crash_find_debug_image(const struct crash_snapshot_module *module,
				  char *path, size_t path_size)
{
	if (path != NULL && path_size > 0)
		path[0] = '\0';
	if (module == NULL || path == NULL || path_size == 0)
		return ETR_INVAL;
	if (crash_find_build_id_debug_image(module, path, path_size) == ETR_OK)
		return ETR_OK;
	if (crash_find_path_debug_image(module, path, path_size) == ETR_OK)
		return ETR_OK;
	return ETR_NOTEXIST;
}

/*
 * Convert the ASLR-stable file-relative PC captured in the snapshot back into
 * the ELF virtual address space expected by ELF/DWARF symbol lookup helpers.
 */
static int crash_symbolize_prepare_vaddr(Elf *elf,
					 struct crash_symbolized_frame *result)
{
	if (result == NULL)
		return ETR_INVAL;
	if (elf_file_offset_to_vaddr(elf, result->file_offset_pc,
				    &result->elf_vaddr) != ETR_OK)
		return ETR_NOTEXIST;
	result->has_elf_vaddr = true;
	return ETR_OK;
}

/*
 * Recover a symbol name from ELF symbol tables. This is cheaper than a full
 * DWARF walk and often succeeds even when source line information is absent.
 */
static int crash_symbolize_elf_symbols(Elf *elf,
				       struct crash_symbolized_frame *result)
{
	const char *symbol_name = NULL;
	uint64_t symbol_addr = 0;
	uint64_t symbol_size = 0;

	if (result == NULL || !result->has_elf_vaddr)
		return ETR_INVAL;
	if (elf_symbolize_pc(elf, result->elf_vaddr, &symbol_name, &symbol_addr,
			     &symbol_size) != ETR_OK)
		return ETR_NOTEXIST;

	crash_set_symbol_name(result, symbol_name, symbol_addr, symbol_size);
	return result->has_symbol ? ETR_OK : ETR_NOTEXIST;
}

/*
 * Decide whether a new DWARF line-table address is a better match than the
 * current one. Stage 2 wants the closest line entry whose address does not
 * exceed the recovered PC.
 */
static int crash_line_match_better(uint64_t candidate_addr,
				 uint64_t best_addr)
{
	return best_addr == 0 || candidate_addr >= best_addr;
}

/*
 * Walk a DIE subtree looking for a subprogram range that contains the target
 * address. When found, DWARF can provide a better function name than stripped
 * or incomplete ELF symbols.
 */
static void crash_symbolize_line_in_die(Dwarf_Debug dbg, Dwarf_Die die,
					struct crash_symbolized_frame *result,
					Dwarf_Error *errp)
{
	Dwarf_Half tag = 0;
	int rc;
	Dwarf_Die child = 0;

	if (dbg == NULL || die == 0 || result == NULL)
		return;

	rc = dwarf_tag(die, &tag, errp);
	if (rc != DW_DLV_OK)
		return;
	if (tag == DW_TAG_subprogram) {
		Dwarf_Addr low_pc = 0;
		Dwarf_Addr high_pc = 0;
		Dwarf_Half highpc_form = 0;
		enum Dwarf_Form_Class highpc_class = DW_FORM_CLASS_UNKNOWN;

		rc = dwarf_lowpc(die, &low_pc, errp);
		if (rc == DW_DLV_OK) {
			rc = dwarf_highpc_b(die, &high_pc, &highpc_form,
					    &highpc_class, errp);
			if (rc == DW_DLV_OK) {
				if (highpc_class == DW_FORM_CLASS_CONSTANT)
					high_pc += low_pc;
				if (result->elf_vaddr >= low_pc &&
				    result->elf_vaddr < high_pc) {
					char *name = NULL;

					if (!result->has_symbol &&
					    dwarf_diename(die, &name, errp) == DW_DLV_OK) {
						crash_set_symbol_name(result, name, low_pc,
							      high_pc - low_pc);
						if (name != NULL)
							dwarf_dealloc(dbg, name,
								      DW_DLA_STRING);
					}
				}
			}
		}
	}

	rc = dwarf_child(die, &child, errp);
	if (rc == DW_DLV_OK) {
		Dwarf_Die current = child;

		for (;;) {
			Dwarf_Die sibling = 0;

			crash_symbolize_line_in_die(dbg, current, result, errp);
			rc = dwarf_siblingof_b(dbg, current, true, &sibling, errp);
			dwarf_dealloc(dbg, current, DW_DLA_DIE);
			if (rc != DW_DLV_OK)
				break;
			current = sibling;
		}
	}
}

/*
 * Use libdwarf line tables to recover source file and line information for the
 * target PC. This path is intentionally best-effort and tolerant of incomplete
 * or partially missing DWARF sections.
 */
static int crash_symbolize_dwarf_lines(int fd,
				      struct crash_symbolized_frame *result)
{
	Dwarf_Debug dbg = 0;
	Dwarf_Error err = 0;
	Dwarf_Bool is_info = 1;
	int rc;
	int ret = ETR_NOTEXIST;

	if (result == NULL || !result->has_elf_vaddr)
		return ETR_INVAL;

	rc = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &err);
	if (rc != DW_DLV_OK)
		return ETR_NOTEXIST;

	for (;;) {
		Dwarf_Die cu_die = 0;
		Dwarf_Die no_die = 0;
		Dwarf_Line_Context line_context = 0;
		Dwarf_Line *linebuf = NULL;
		Dwarf_Signed linecount = 0;
		Dwarf_Signed i;
		uint64_t best_addr = 0;
		int have_match = 0;

		rc = dwarf_next_cu_header_d(dbg, is_info, NULL, NULL, NULL, NULL,
					     NULL, NULL, NULL, NULL, NULL,
					     NULL, &err);
		if (rc != DW_DLV_OK)
			break;
		rc = dwarf_siblingof_b(dbg, no_die, is_info, &cu_die, &err);
		if (rc != DW_DLV_OK)
			continue;

		crash_symbolize_line_in_die(dbg, cu_die, result, &err);
		rc = dwarf_srclines_b(cu_die, NULL, NULL, &line_context, &err);
		if (rc == DW_DLV_OK) {
			rc = dwarf_srclines_from_linecontext(line_context, &linebuf,
						     &linecount, &err);
			if (rc == DW_DLV_OK) {
				for (i = 0; i < linecount; i++) {
					Dwarf_Addr line_addr = 0;
					Dwarf_Unsigned line_no = 0;
					Dwarf_Bool end_sequence = 0;
					char *line_src = NULL;

					if (dwarf_lineaddr(linebuf[i], &line_addr, &err) !=
					    DW_DLV_OK)
						continue;
					if (line_addr > result->elf_vaddr)
						continue;
					if (dwarf_lineendsequence(linebuf[i], &end_sequence,
							  &err) == DW_DLV_OK &&
					    end_sequence)
						continue;
					if (!crash_line_match_better(line_addr, best_addr))
						continue;
					if (dwarf_lineno(linebuf[i], &line_no, &err) !=
					    DW_DLV_OK)
						continue;
					if (dwarf_linesrc(linebuf[i], &line_src, &err) !=
					    DW_DLV_OK)
						line_src = NULL;

					best_addr = line_addr;
					result->line = line_no;
					crash_copy_cstr(result->file_path,
							sizeof(result->file_path),
							line_src != NULL ? line_src :
							"<unknown>");
					if (line_src != NULL)
						dwarf_dealloc(dbg, line_src,
							      DW_DLA_STRING);
					result->has_line = true;
					have_match = 1;
				}
			}
			dwarf_srclines_dealloc_b(line_context);
		}
		dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
		if (have_match)
			ret = ETR_OK;
	}

	if (err != 0)
		dwarf_dealloc_error(dbg, err);
	(void)dwarf_finish(dbg);
	return ret;
}

/*
 * Symbolize one recovered frame.
 *
 * Resolution order is:
 *   1. use the snapshot's module_index/rel_pc pair to find the owning module,
 *   2. reconstruct a file-relative PC and map it into ELF virtual address space,
 *   3. prefer a matching external debuginfo image when available,
 *   4. fall back to the original module's own ELF and DWARF data,
 *   5. return whatever partial information was recovered.
 */
static int crash_symbolize_frame(const struct crash_snapshot_record *record,
				 const struct crash_snapshot_frame *frame,
				 struct crash_symbolized_frame *result)
{
	Elf *elf = NULL;
	Elf *debug_elf = NULL;
	char debug_path[PATH_MAX];
	int fd = -1;
	int debug_fd = -1;
	int ret;

	memset(result, 0, sizeof(*result));
	if (crash_find_module(record, frame, &result->module) != ETR_OK)
		return ETR_NOTEXIST;
	result->has_module = true;
	result->file_offset_pc = result->module->file_offset + frame->rel_pc;

	if (openelf(result->module->path, &elf, &fd) != 0)
		return ETR_NOTEXIST;

	ret = crash_symbolize_prepare_vaddr(elf, result);
	if (ret != ETR_OK)
		goto out;

	if (crash_find_debug_image(result->module, debug_path,
				   sizeof(debug_path)) == ETR_OK &&
	    openelf(debug_path, &debug_elf, &debug_fd) == 0) {
		(void)crash_symbolize_elf_symbols(debug_elf, result);
		(void)crash_symbolize_dwarf_lines(debug_fd, result);
	}
	if (!result->has_symbol)
		(void)crash_symbolize_elf_symbols(elf, result);
	if (!result->has_line)
		(void)crash_symbolize_dwarf_lines(fd, result);
	ret = ETR_OK;

out:
	if (debug_elf != NULL)
		elf_end(debug_elf);
	if (debug_fd >= 0)
		close(debug_fd);
	if (elf != NULL)
		elf_end(elf);
	if (fd >= 0)
		close(fd);
	return ret;
}

/*
 * Emit the crash-level summary line recovered from the snapshot header. This is
 * useful even when every per-frame symbol lookup later falls back to raw data.
 */
static void crash_log_summary(const struct crash_snapshot_record *record,
			      uint32_t frames)
{
	ebpf_warning("Recovered crash snapshot: signal=%u code=%d pid=%u tid=%u executable=%s ip=0x%llx fault_addr=0x%llx frames=%u\n",
		     record->signal, record->si_code, record->pid, record->tid,
		     record->executable_path[0] ? record->executable_path : "<unknown>",
		     (unsigned long long)record->ip,
		     (unsigned long long)record->fault_addr, frames);
}

/*
 * Fallback logging for frames that could not be fully symbolized. The goal is
 * to preserve at least the raw PC, plus module/rel_pc/build-id when Stage 1
 * had enough metadata to identify the owning image.
 */
static void crash_log_raw_frame(uint32_t index,
				const struct crash_snapshot_frame *frame,
				const struct crash_symbolized_frame *symbolized)
{
	const char *module_path = "<unknown>";
	char build_id[CRASH_SNAPSHOT_BUILD_ID_SIZE * 2 + 1];

	build_id[0] = '\0';
	if (symbolized != NULL && symbolized->has_module) {
		module_path = symbolized->module->path[0] ? symbolized->module->path :
		    "<unknown>";
		crash_format_build_id(symbolized->module, build_id, sizeof(build_id));
	}
	if (build_id[0] != '\0') {
		ebpf_warning("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx build_id=%s\n",
			     index, (unsigned long long)frame->absolute_pc, module_path,
			     (unsigned long long)frame->rel_pc, build_id);
		return;
	}
	if (symbolized != NULL && symbolized->has_module) {
		ebpf_warning("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx\n",
			     index, (unsigned long long)frame->absolute_pc, module_path,
			     (unsigned long long)frame->rel_pc);
		return;
	}
	ebpf_warning("Recovered crash frame[%u]: pc=0x%llx\n", index,
		     (unsigned long long)frame->absolute_pc);
}

/*
 * Return the frame's offset inside the resolved symbol, if both values are
 * known. This is the familiar function+0xNN form used in crash reports.
 */
static uint64_t crash_symbol_offset(const struct crash_symbolized_frame *symbolized)
{
	if (symbolized == NULL || !symbolized->has_symbol ||
	    symbolized->elf_vaddr < symbolized->symbol_addr)
		return 0;
	return symbolized->elf_vaddr - symbolized->symbol_addr;
}

/*
 * Emit the richest per-frame representation that Stage 2 managed to recover.
 * The format intentionally degrades from symbol+file:line down to raw module
 * metadata without treating partial recovery as an error.
 */
static void crash_log_symbolized_frame(uint32_t index,
				       const struct crash_snapshot_frame *frame,
				       const struct crash_symbolized_frame *symbolized)
{
	const char *module_path = symbolized->module->path[0] ?
	    symbolized->module->path : "<unknown>";
	const char *symbol_name = symbolized->symbol_name[0] ?
	    symbolized->symbol_name : "<unknown>";
	uint64_t symbol_offset = crash_symbol_offset(symbolized);
	char build_id[CRASH_SNAPSHOT_BUILD_ID_SIZE * 2 + 1];

	crash_format_build_id(symbolized->module, build_id, sizeof(build_id));
	if (symbolized->has_line && symbolized->has_symbol) {
		if (build_id[0] != '\0') {
			ebpf_warning("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx symbol=%s+0x%llx file=%s:%llu build_id=%s\n",
			     index, (unsigned long long)frame->absolute_pc, module_path,
			     (unsigned long long)frame->rel_pc, symbol_name,
			     (unsigned long long)symbol_offset, symbolized->file_path,
			     (unsigned long long)symbolized->line, build_id);
			return;
		}
		ebpf_warning("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx symbol=%s+0x%llx file=%s:%llu\n",
			     index, (unsigned long long)frame->absolute_pc, module_path,
			     (unsigned long long)frame->rel_pc, symbol_name,
			     (unsigned long long)symbol_offset, symbolized->file_path,
			     (unsigned long long)symbolized->line);
		return;
	}
	if (symbolized->has_line) {
		if (build_id[0] != '\0') {
			ebpf_warning("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx file=%s:%llu build_id=%s\n",
			     index, (unsigned long long)frame->absolute_pc, module_path,
			     (unsigned long long)frame->rel_pc, symbolized->file_path,
			     (unsigned long long)symbolized->line, build_id);
			return;
		}
		ebpf_warning("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx file=%s:%llu\n",
			     index, (unsigned long long)frame->absolute_pc, module_path,
			     (unsigned long long)frame->rel_pc, symbolized->file_path,
			     (unsigned long long)symbolized->line);
		return;
	}
	if (build_id[0] != '\0') {
		ebpf_warning("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx symbol=%s+0x%llx build_id=%s\n",
			     index, (unsigned long long)frame->absolute_pc, module_path,
			     (unsigned long long)frame->rel_pc, symbol_name,
			     (unsigned long long)symbol_offset, build_id);
		return;
	}
	ebpf_warning("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx symbol=%s+0x%llx\n",
		     index, (unsigned long long)frame->absolute_pc, module_path,
		     (unsigned long long)frame->rel_pc, symbol_name,
		     (unsigned long long)symbol_offset);
}

/*
 * Stage-2 entry point for one persisted crash snapshot record.
 *
 * A recovered record may contain a mix of fully symbolizable frames and frames
 * whose module, symbol, or line metadata can no longer be reconstructed. The
 * consumer therefore treats symbolization strictly as a per-frame best-effort
 * operation: emit the crash-level summary first, then log each frame with the
 * richest representation available, and fall back to raw-PC output when needed
 * without aborting the rest of the record.
 */
int crash_symbolize_record(const struct crash_snapshot_record *record)
{
	uint32_t frames;
	uint32_t i;

	if (record == NULL)
		return ETR_INVAL;

	frames = record->frames_count;
	if (frames > CRASH_SNAPSHOT_MAX_FRAMES)
		frames = CRASH_SNAPSHOT_MAX_FRAMES;
	crash_log_summary(record, frames);
	for (i = 0; i < frames; i++) {
		struct crash_symbolized_frame symbolized;

		if (crash_symbolize_frame(record, &record->frames[i], &symbolized) ==
		    ETR_OK && symbolized.has_module &&
		    (symbolized.has_symbol || symbolized.has_line)) {
			crash_log_symbolized_frame(i, &record->frames[i], &symbolized);
			continue;
		}
		crash_log_raw_frame(i, &record->frames[i], &symbolized);
	}
	return ETR_OK;
}
