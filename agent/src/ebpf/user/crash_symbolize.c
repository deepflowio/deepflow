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
#define CRASH_REPORT_SEPARATOR "========================================================="

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

struct crash_md5_context {
	uint32_t state[4];
	uint64_t total_size;
	uint8_t block[64];
	size_t block_size;
};

static uint32_t crash_md5_load_le32(const uint8_t *src)
{
	return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
	       ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

static void crash_md5_store_le32(uint8_t *dst, uint32_t value)
{
	dst[0] = (uint8_t)value;
	dst[1] = (uint8_t)(value >> 8);
	dst[2] = (uint8_t)(value >> 16);
	dst[3] = (uint8_t)(value >> 24);
}

static uint32_t crash_md5_left_rotate(uint32_t value, uint32_t shift)
{
	return (value << shift) | (value >> (32 - shift));
}

/*
 * Stage-2 computes an executable MD5 only for operator-facing crash summaries.
 * The digest is never used for trust decisions; it is purely a convenient
 * fingerprint for checking which exact on-disk image produced the recovered
 * snapshot.
 */
static void crash_md5_transform(struct crash_md5_context *ctx,
				const uint8_t block[64])
{
	static const uint32_t shift[64] = {
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
	};
	static const uint32_t table[64] = {
		0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU,
		0xf57c0fafU, 0x4787c62aU, 0xa8304613U, 0xfd469501U,
		0x698098d8U, 0x8b44f7afU, 0xffff5bb1U, 0x895cd7beU,
		0x6b901122U, 0xfd987193U, 0xa679438eU, 0x49b40821U,
		0xf61e2562U, 0xc040b340U, 0x265e5a51U, 0xe9b6c7aaU,
		0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U,
		0x21e1cde6U, 0xc33707d6U, 0xf4d50d87U, 0x455a14edU,
		0xa9e3e905U, 0xfcefa3f8U, 0x676f02d9U, 0x8d2a4c8aU,
		0xfffa3942U, 0x8771f681U, 0x6d9d6122U, 0xfde5380cU,
		0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U,
		0x289b7ec6U, 0xeaa127faU, 0xd4ef3085U, 0x04881d05U,
		0xd9d4d039U, 0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U,
		0xf4292244U, 0x432aff97U, 0xab9423a7U, 0xfc93a039U,
		0x655b59c3U, 0x8f0ccc92U, 0xffeff47dU, 0x85845dd1U,
		0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U,
		0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U,
	};
	uint32_t words[16];
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t f;
	uint32_t g;
	uint32_t temp;
	size_t i;

	if (ctx == NULL)
		return;
	for (i = 0; i < 16; i++)
		words[i] = crash_md5_load_le32(block + i * 4);

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];

	for (i = 0; i < 64; i++) {
		if (i < 16) {
			f = (b & c) | (~b & d);
			g = (uint32_t)i;
		} else if (i < 32) {
			f = (d & b) | (~d & c);
			g = (uint32_t)((i * 5 + 1) & 0xf);
		} else if (i < 48) {
			f = b ^ c ^ d;
			g = (uint32_t)((i * 3 + 5) & 0xf);
		} else {
			f = c ^ (b | ~d);
			g = (uint32_t)((i * 7) & 0xf);
		}

		temp = d;
		d = c;
		c = b;
		b += crash_md5_left_rotate(a + f + table[i] + words[g], shift[i]);
		a = temp;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
}

static void crash_md5_init(struct crash_md5_context *ctx)
{
	if (ctx == NULL)
		return;
	memset(ctx, 0, sizeof(*ctx));
	ctx->state[0] = 0x67452301U;
	ctx->state[1] = 0xefcdab89U;
	ctx->state[2] = 0x98badcfeU;
	ctx->state[3] = 0x10325476U;
}

static void crash_md5_update(struct crash_md5_context *ctx,
				     const uint8_t *data, size_t data_size)
{
	size_t copy_size;

	if (ctx == NULL || data == NULL || data_size == 0)
		return;

	ctx->total_size += data_size;
	if (ctx->block_size != 0) {
		copy_size = sizeof(ctx->block) - ctx->block_size;
		if (copy_size > data_size)
			copy_size = data_size;
		memcpy(ctx->block + ctx->block_size, data, copy_size);
		ctx->block_size += copy_size;
		data += copy_size;
		data_size -= copy_size;
		if (ctx->block_size == sizeof(ctx->block)) {
			crash_md5_transform(ctx, ctx->block);
			ctx->block_size = 0;
		}
	}

	while (data_size >= sizeof(ctx->block)) {
		crash_md5_transform(ctx, data);
		data += sizeof(ctx->block);
		data_size -= sizeof(ctx->block);
	}
	if (data_size == 0)
		return;
	memcpy(ctx->block, data, data_size);
	ctx->block_size = data_size;
}

static void crash_md5_final(struct crash_md5_context *ctx, uint8_t digest[16])
{
	static const uint8_t padding[64] = { 0x80 };
	uint8_t size_le[8];
	uint64_t total_bits;
	size_t padding_size;
	size_t i;

	if (ctx == NULL || digest == NULL)
		return;

	total_bits = ctx->total_size * 8;
	for (i = 0; i < sizeof(size_le); i++)
		size_le[i] = (uint8_t)(total_bits >> (i * 8));
	padding_size = (ctx->block_size < 56) ? (56 - ctx->block_size) :
		(sizeof(ctx->block) + 56 - ctx->block_size);
	crash_md5_update(ctx, padding, padding_size);
	crash_md5_update(ctx, size_le, sizeof(size_le));
	for (i = 0; i < 4; i++)
		crash_md5_store_le32(digest + i * 4, ctx->state[i]);
}

static void crash_format_md5(const uint8_t digest[16], char *buf,
			     size_t buf_size)
{
	static const char hex[] = "0123456789abcdef";
	size_t i;

	if (buf == NULL || buf_size == 0)
		return;
	buf[0] = '\0';
	if (digest == NULL || buf_size < 33)
		return;
	for (i = 0; i < 16; i++) {
		buf[i * 2] = hex[digest[i] >> 4];
		buf[i * 2 + 1] = hex[digest[i] & 0xf];
	}
	buf[32] = '\0';
}

static int crash_md5_file(const char *path, char *buf, size_t buf_size)
{
	struct crash_md5_context md5;
	uint8_t digest[16];
	uint8_t data[4096];
	ssize_t nread;
	int fd;

	if (buf != NULL && buf_size > 0)
		buf[0] = '\0';
	if (path == NULL || path[0] == '\0' || buf == NULL || buf_size < 33)
		return ETR_INVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return ETR_NOTEXIST;

	crash_md5_init(&md5);
	while ((nread = read(fd, data, sizeof(data))) > 0)
		crash_md5_update(&md5, data, (size_t)nread);
	close(fd);
	if (nread < 0)
		return ETR_INVAL;

	crash_md5_final(&md5, digest);
	crash_format_md5(digest, buf, buf_size);
	return ETR_OK;
}

static const char *crash_executable_name(const char *path)
{
	const char *name;

	if (path == NULL || path[0] == '\0')
		return "<unknown>";
	name = strrchr(path, '/');
	if (name != NULL && name[1] != '\0')
		return name + 1;
	return path;
}

/*
 * Return the best human-readable task name available for the recovered crash.
 *
 * New-format snapshots store the kernel task name directly in thread_name.
 * Older records do not have that field, so Stage 2 falls back to the basename
 * of the executable path rather than leaving the summary completely unnamed.
 */
static const char *crash_record_task_name(const struct crash_snapshot_record *record)
{
	if (record == NULL)
		return "<unknown>";
	if (record->thread_name[0] != '\0')
		return record->thread_name;
	if (record->executable_path[0] != '\0')
		return crash_executable_name(record->executable_path);
	return "<unknown>";
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
static int crash_debug_file_matches_build_id(const struct crash_snapshot_module
					     *module, const char *path)
{
	uint8_t build_id[CRASH_SNAPSHOT_BUILD_ID_SIZE];
	uint32_t build_id_size = 0;

	if (module == NULL || path == NULL)
		return 0;
	if (module->build_id_size == 0)
		return 1;
	if (elf_read_build_id(path, build_id, sizeof(build_id), &build_id_size)
	    != ETR_OK)
		return 1;
	if (build_id_size != module->build_id_size)
		return 0;
	return memcmp(build_id, module->build_id, build_id_size) == 0;
}

/*
 * Look for split debuginfo in the standard build-id hierarchy used by many
 * distros: /usr/lib/debug/.build-id/xx/yyyy....debug.
 */
static int crash_find_build_id_debug_image(const struct crash_snapshot_module
					   *module, char *path,
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

	len =
	    snprintf(path, path_size, "/usr/lib/debug/.build-id/%c%c/%s.debug",
		     build_id[0], build_id[1], build_id + 2);
	if (len < 0 || (size_t) len >= path_size)
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
static int crash_find_path_debug_image(const struct crash_snapshot_module
				       *module, char *path, size_t path_size)
{
	int len;

	if (path != NULL && path_size > 0)
		path[0] = '\0';
	if (module == NULL || path == NULL || path_size == 0 ||
	    module->path[0] != '/')
		return ETR_NOTEXIST;

	len = snprintf(path, path_size, "/usr/lib/debug%s.debug", module->path);
	if (len < 0 || (size_t) len >= path_size)
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
static int crash_symbolize_prepare_vaddr(Elf * elf,
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
static int crash_symbolize_elf_symbols(Elf * elf,
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
static int crash_line_match_better(uint64_t candidate_addr, uint64_t best_addr)
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
					Dwarf_Error * errp)
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
					    dwarf_diename(die, &name,
							  errp) == DW_DLV_OK) {
						crash_set_symbol_name(result,
								      name,
								      low_pc,
								      high_pc -
								      low_pc);
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
			rc = dwarf_siblingof_b(dbg, current, true, &sibling,
					       errp);
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
 *
 * libelf and libdwarf keep independent state over file descriptors, so the
 * DWARF reader opens its own fd instead of reusing the one already owned by
 * openelf(). Some libdwarf builds are also stricter about dwarf_srclines_b()
 * output arguments, so pass real storage for all out-parameters instead of
 * NULL placeholders.
 */
static int crash_symbolize_dwarf_lines(const char *path,
				       struct crash_symbolized_frame *result)
{
	Dwarf_Debug dbg = 0;
	Dwarf_Error err = 0;
	Dwarf_Bool is_info = 1;
	uint64_t best_addr = 0;
	int have_match = 0;
	int fd = -1;
	int rc;
	int ret = ETR_NOTEXIST;

	if (path == NULL || path[0] == '\0' || result == NULL ||
	    !result->has_elf_vaddr)
		return ETR_INVAL;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return ETR_NOTEXIST;

	rc = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &err);
	if (rc != DW_DLV_OK) {
		close(fd);
		return ETR_NOTEXIST;
	}

	for (;;) {
		Dwarf_Die cu_die = 0;
		Dwarf_Die no_die = 0;
		Dwarf_Line_Context line_context = 0;
		Dwarf_Line *linebuf = NULL;
		Dwarf_Signed linecount = 0;
		Dwarf_Signed i;
		Dwarf_Bool has_stmt_list = 0;
		Dwarf_Unsigned line_version = 0;
		Dwarf_Small table_count = 0;

		rc = dwarf_next_cu_header_d(dbg, is_info, NULL, NULL, NULL,
					    NULL, NULL, NULL, NULL, NULL, NULL,
					    NULL, &err);
		if (rc != DW_DLV_OK)
			break;
		rc = dwarf_siblingof_b(dbg, no_die, is_info, &cu_die, &err);
		if (rc != DW_DLV_OK)
			continue;

		crash_symbolize_line_in_die(dbg, cu_die, result, &err);
		rc = dwarf_hasattr(cu_die, DW_AT_stmt_list, &has_stmt_list,
				   &err);
		if (rc != DW_DLV_OK || !has_stmt_list) {
			dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
			continue;
		}
		rc = dwarf_srclines_b(cu_die, &line_version, &table_count,
				      &line_context, &err);
		if (rc == DW_DLV_OK) {
			rc = dwarf_srclines_from_linecontext(line_context,
							     &linebuf,
							     &linecount, &err);
			if (rc == DW_DLV_OK) {
				for (i = 0; i < linecount; i++) {
					Dwarf_Addr line_addr = 0;
					Dwarf_Unsigned line_no = 0;
					Dwarf_Bool end_sequence = 0;
					char *line_src = NULL;

					if (dwarf_lineaddr
					    (linebuf[i], &line_addr,
					     &err) != DW_DLV_OK)
						continue;
					if (line_addr > result->elf_vaddr)
						continue;
					if (dwarf_lineendsequence
					    (linebuf[i], &end_sequence,
					     &err) == DW_DLV_OK && end_sequence)
						continue;
					/*
					 * Choose the closest line-table row across the whole DWARF
					 * dataset, not just within the current CU. Resetting the
					 * best match per CU makes the last matching CU win, which
					 * can pin unrelated frames to a single source line.
					 */
					if (!crash_line_match_better
					    (line_addr, best_addr))
						continue;
					if (dwarf_lineno
					    (linebuf[i], &line_no,
					     &err) != DW_DLV_OK)
						continue;
					if (dwarf_linesrc
					    (linebuf[i], &line_src,
					     &err) != DW_DLV_OK)
						line_src = NULL;

					best_addr = line_addr;
					result->line = line_no;
					crash_copy_cstr(result->file_path,
							sizeof(result->
							       file_path),
							line_src !=
							NULL ? line_src :
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
	}

	if (have_match)
		ret = ETR_OK;
	if (err != 0)
		dwarf_dealloc_error(dbg, err);
	(void)dwarf_finish(dbg);
	close(fd);
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
		(void)crash_symbolize_dwarf_lines(debug_path, result);
	}
	if (!result->has_symbol)
		(void)crash_symbolize_elf_symbols(elf, result);
	if (!result->has_line)
		(void)crash_symbolize_dwarf_lines(result->module->path, result);
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
 * Emit the crash-level summary recovered from the snapshot header.
 *
 * Beyond the raw signal/register values, operators usually want to know which
 * task crashed and whether the recovered executable still matches the image on
 * disk. The task name comes from Stage 1 when available, while the MD5 is a
 * best-effort Stage-2 calculation against the recorded executable path. The
 * raw top-frame ABI argument registers are logged separately right after the
 * summary so the main headline remains grep-friendly.
 */
static void crash_log_summary(const struct crash_snapshot_record *record,
			      uint32_t frames)
{
	char executable_md5[33];
	const char *task_name;
	const char *executable_path;
	const char *md5_text = "<unavailable>";

	task_name = crash_record_task_name(record);
	executable_path = record->executable_path[0] ?
		record->executable_path : "<unknown>";
	if (record->executable_path[0] != '\0' &&
	    crash_md5_file(record->executable_path, executable_md5,
			   sizeof(executable_md5)) == ETR_OK)
		md5_text = executable_md5;
	/*
	 * Use one summary line so operators can grep recovered crashes easily while
	 * still seeing the task name and image fingerprint immediately.
	 */
	ebpf_info
	    ("Recovered crash snapshot: task=%s signal=%u code=%d pid=%u tid=%u executable=%s executable_md5=%s ip=0x%llx fault_addr=0x%llx frames=%u\n",
	     task_name, record->signal, record->si_code, record->pid,
	     record->tid, executable_path, md5_text,
	     (unsigned long long)record->ip,
	     (unsigned long long)record->fault_addr, frames);
}

/*
 * Emit the raw top-frame ABI argument registers captured in the snapshot.
 *
 * These values come straight from the crashing thread's register context. They
 * are useful as low-level clues when inspecting the recovered top frame, but
 * they are intentionally not presented as reconstructed source-language
 * arguments: stack-passed values, floating-point registers, optimized-out
 * parameters, and older-frame arguments are outside the guarantees of the
 * snapshot format.
 */
static void crash_log_args(const struct crash_snapshot_record *record)
{
	if (record == NULL)
		return;

	switch (record->arch) {
	case CRASH_SNAPSHOT_ARCH_X86_64:
		ebpf_info
		    ("Recovered crash args: rdi=0x%llx rsi=0x%llx rdx=0x%llx rcx=0x%llx r8=0x%llx r9=0x%llx\n",
		     (unsigned long long)record->args[0],
		     (unsigned long long)record->args[1],
		     (unsigned long long)record->args[2],
		     (unsigned long long)record->args[3],
		     (unsigned long long)record->args[4],
		     (unsigned long long)record->args[5]);
		return;
	case CRASH_SNAPSHOT_ARCH_AARCH64:
		ebpf_info
		    ("Recovered crash args: x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx x4=0x%llx x5=0x%llx x6=0x%llx x7=0x%llx\n",
		     (unsigned long long)record->args[0],
		     (unsigned long long)record->args[1],
		     (unsigned long long)record->args[2],
		     (unsigned long long)record->args[3],
		     (unsigned long long)record->args[4],
		     (unsigned long long)record->args[5],
		     (unsigned long long)record->args[6],
		     (unsigned long long)record->args[7]);
		return;
	default:
		ebpf_info
		    ("Recovered crash args: arg0=0x%llx arg1=0x%llx arg2=0x%llx arg3=0x%llx arg4=0x%llx arg5=0x%llx arg6=0x%llx arg7=0x%llx\n",
		     (unsigned long long)record->args[0],
		     (unsigned long long)record->args[1],
		     (unsigned long long)record->args[2],
		     (unsigned long long)record->args[3],
		     (unsigned long long)record->args[4],
		     (unsigned long long)record->args[5],
		     (unsigned long long)record->args[6],
		     (unsigned long long)record->args[7]);
		return;
	}
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
		module_path =
		    symbolized->module->path[0] ? symbolized->module->
		    path : "<unknown>";
		crash_format_build_id(symbolized->module, build_id,
				      sizeof(build_id));
	}
	if (build_id[0] != '\0') {
		ebpf_warning
		    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx build_id=%s\n",
		     index, (unsigned long long)frame->absolute_pc, module_path,
		     (unsigned long long)frame->rel_pc, build_id);
		return;
	}
	if (symbolized != NULL && symbolized->has_module) {
		ebpf_warning
		    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx\n",
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
static uint64_t crash_symbol_offset(const struct crash_symbolized_frame
				    *symbolized)
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
				       const struct crash_symbolized_frame
				       *symbolized)
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
			ebpf_info
			    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx symbol=%s+0x%llx file=%s:%llu build_id=%s\n",
			     index, (unsigned long long)frame->absolute_pc,
			     module_path, (unsigned long long)frame->rel_pc,
			     symbol_name, (unsigned long long)symbol_offset,
			     symbolized->file_path,
			     (unsigned long long)symbolized->line, build_id);
			return;
		}
		ebpf_info
		    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx symbol=%s+0x%llx file=%s:%llu\n",
		     index, (unsigned long long)frame->absolute_pc, module_path,
		     (unsigned long long)frame->rel_pc, symbol_name,
		     (unsigned long long)symbol_offset, symbolized->file_path,
		     (unsigned long long)symbolized->line);
		return;
	}
	if (symbolized->has_line) {
		if (build_id[0] != '\0') {
			ebpf_info
			    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx file=%s:%llu build_id=%s\n",
			     index, (unsigned long long)frame->absolute_pc,
			     module_path, (unsigned long long)frame->rel_pc,
			     symbolized->file_path,
			     (unsigned long long)symbolized->line, build_id);
			return;
		}
		ebpf_info
		    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx file=%s:%llu\n",
		     index, (unsigned long long)frame->absolute_pc, module_path,
		     (unsigned long long)frame->rel_pc, symbolized->file_path,
		     (unsigned long long)symbolized->line);
		return;
	}
	if (build_id[0] != '\0') {
		ebpf_info
		    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx symbol=%s+0x%llx build_id=%s\n",
		     index, (unsigned long long)frame->absolute_pc, module_path,
		     (unsigned long long)frame->rel_pc, symbol_name,
		     (unsigned long long)symbol_offset, build_id);
		return;
	}
	ebpf_info
	    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx symbol=%s+0x%llx\n",
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
 * operation: bracket the recovered report with clear separators, emit the
 * crash-level summary first, then log each frame with the richest
 * representation available, and fall back to raw-PC output when needed without
 * aborting the rest of the record.
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
	ebpf_info("%s\n", CRASH_REPORT_SEPARATOR);
	crash_log_summary(record, frames);
	crash_log_args(record);
	for (i = 0; i < frames; i++) {
		struct crash_symbolized_frame symbolized;

		if (crash_symbolize_frame
		    (record, &record->frames[i], &symbolized) == ETR_OK
		    && symbolized.has_module && (symbolized.has_symbol
						 || symbolized.has_line)) {
			crash_log_symbolized_frame(i, &record->frames[i],
						   &symbolized);
			continue;
		}
		crash_log_raw_frame(i, &record->frames[i], &symbolized);
	}
	ebpf_info("%s\n", CRASH_REPORT_SEPARATOR);
	return ETR_OK;
}
