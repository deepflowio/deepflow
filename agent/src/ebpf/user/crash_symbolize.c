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
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "elf.h"
#include "log.h"
#include "utils.h"

#define CRASH_SYMBOL_NAME_LEN 256
#define CRASH_PARAM_TEXT_LEN 1024
#define CRASH_PARAM_NAME_LEN 128
#define CRASH_PARAM_LOCATION_LEN 128
#define CRASH_DWARF_EXPR_LEN_MAX 128
#define CRASH_DWARF_EXPR_STACK_MAX 8
#define CRASH_DWARF_REF_DEPTH_MAX 8
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
	char params_text[CRASH_PARAM_TEXT_LEN];
	uint64_t line;
	bool has_module;
	bool has_elf_vaddr;
	bool has_symbol;
	bool has_line;
	bool has_params;
};

struct crash_param_eval_context {
	const struct crash_snapshot_record *record;
	const struct crash_snapshot_frame *frame;
	uint64_t pc;
	uint64_t frame_pc;
	uint64_t frame_base;
	uint64_t call_frame_cfa;
	char frame_base_location[CRASH_PARAM_LOCATION_LEN];
	char call_frame_cfa_location[CRASH_PARAM_LOCATION_LEN];
	bool has_frame_base;
	bool has_call_frame_cfa;
};

struct crash_expr_stack_item {
	uint64_t value;
	char location[CRASH_PARAM_LOCATION_LEN];
	bool has_value;
	bool is_address;
	bool has_location;
};

struct crash_expr_value {
	uint64_t value;
	char location[CRASH_PARAM_LOCATION_LEN];
	uint8_t byte_size;
	bool has_value;
	bool is_address;
	bool has_location;
};

struct crash_param_value {
	uint64_t value;
	char location[CRASH_PARAM_LOCATION_LEN];
	uint8_t byte_size;
	bool has_value;
	bool has_location;
};

static int crash_record_has_full_regs(const struct crash_snapshot_record *record);

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
 * Older frames often have to match a DWARF subprogram against an ELF-derived
 * symbol name because some debug images omit low/high PC on declaration DIEs or
 * express ranges in ways this best-effort path does not fully evaluate.
 *
 * Normalize common compiler/linker suffixes before comparing names so forms
 * like foo.isra.0, foo.constprop.3, foo.cold, or versioned symbols still match
 * the underlying subprogram name.
 */
static char *crash_find_symbol_name_cut(char *name)
{
	static const char *const suffixes[] = {
		".isra",
		".constprop",
		".part",
		".cold",
		".clone",
		".llvm.",
	};
	char *cut = NULL;
	char *candidate;
	size_t i;

	if (name == NULL || name[0] == '\0')
		return NULL;

	candidate = strstr(name, "@@");
	if (candidate != NULL)
		cut = candidate;
	candidate = strchr(name, '@');
	if (candidate != NULL && (cut == NULL || candidate < cut))
		cut = candidate;
	for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
		candidate = strstr(name, suffixes[i]);
		if (candidate != NULL && (cut == NULL || candidate < cut))
			cut = candidate;
	}
	return cut;
}

static void crash_normalize_symbol_name(const char *src, char *dst,
				       size_t dst_size)
{
	char *cut;

	if (dst == NULL || dst_size == 0)
		return;
	dst[0] = '\0';
	if (src == NULL || src[0] == '\0')
		return;

	crash_copy_cstr(dst, dst_size, src);
	cut = crash_find_symbol_name_cut(dst);
	if (cut != NULL)
		*cut = '\0';
}

static int crash_symbol_names_match(const char *lhs, const char *rhs)
{
	char lhs_name[CRASH_SYMBOL_NAME_LEN];
	char rhs_name[CRASH_SYMBOL_NAME_LEN];

	crash_normalize_symbol_name(lhs, lhs_name, sizeof(lhs_name));
	crash_normalize_symbol_name(rhs, rhs_name, sizeof(rhs_name));
	if (lhs_name[0] == '\0' || rhs_name[0] == '\0')
		return 0;
	return strcmp(lhs_name, rhs_name) == 0;
}

static size_t crash_appendf(char *dst, size_t dst_size, size_t offset,
			    const char *fmt, ...)
{
	va_list ap;
	int written;

	if (dst == NULL || dst_size == 0)
		return offset;
	if (offset >= dst_size)
		return dst_size - 1;

	va_start(ap, fmt);
	written = vsnprintf(dst + offset, dst_size - offset, fmt, ap);
	va_end(ap);
	if (written < 0)
		return offset;
	if ((size_t)written >= dst_size - offset)
		return dst_size - 1;
	return offset + (size_t)written;
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
 * Non-top frames captured by the Stage-1 frame-pointer walk or LR hint hold a
 * saved return address rather than the exact call instruction. Most symbol/DWARF
 * consumers want a PC that still falls inside the caller's instruction range, so
 * normalize those frames to the previous byte before looking up symbols,
 * line-table rows, or location lists.
 */
static uint64_t crash_lookup_pc_for_frame(const struct crash_snapshot_frame *frame,
					  uint64_t pc)
{
	if (frame == NULL || pc == 0)
		return pc;
	if ((frame->frame_flags & CRASH_SNAPSHOT_FRAME_TOP) != 0)
		return pc;
	return pc - 1;
}

/*
 * Convert the ASLR-stable file-relative PC captured in the snapshot back into
 * the ELF virtual address space expected by ELF/DWARF symbol lookup helpers.
 */
static int crash_symbolize_prepare_vaddr(Elf * elf,
					 const struct crash_snapshot_frame *frame,
					 struct crash_symbolized_frame *result)
{
	if (result == NULL)
		return ETR_INVAL;
	if (elf_file_offset_to_vaddr(elf, result->file_offset_pc,
				     &result->elf_vaddr) != ETR_OK)
		return ETR_NOTEXIST;
	result->elf_vaddr = crash_lookup_pc_for_frame(frame, result->elf_vaddr);
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

static int crash_top_frame_abi_value(const struct crash_snapshot_record *record,
				     const struct crash_snapshot_frame *frame,
				     uint32_t param_index, uint64_t *value,
				     const char **location_name)
{
	static const char *const x86_64_regs[] = {
		"rdi", "rsi", "rdx", "rcx", "r8", "r9",
	};
	static const char *const aarch64_regs[] = {
		"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
	};

	if (value != NULL)
		*value = 0;
	if (location_name != NULL)
		*location_name = NULL;
	if (record == NULL || frame == NULL ||
	    (frame->frame_flags & CRASH_SNAPSHOT_FRAME_TOP) == 0)
		return ETR_NOTEXIST;

	switch (record->arch) {
	case CRASH_SNAPSHOT_ARCH_X86_64:
		if (param_index >= sizeof(x86_64_regs) / sizeof(x86_64_regs[0]))
			return ETR_NOTEXIST;
		if (value != NULL)
			*value = record->args[param_index];
		if (location_name != NULL)
			*location_name = x86_64_regs[param_index];
		return ETR_OK;
	case CRASH_SNAPSHOT_ARCH_AARCH64:
		if (param_index >= sizeof(aarch64_regs) / sizeof(aarch64_regs[0]))
			return ETR_NOTEXIST;
		if (value != NULL)
			*value = record->args[param_index];
		if (location_name != NULL)
			*location_name = aarch64_regs[param_index];
		return ETR_OK;
	default:
		return ETR_NOTEXIST;
	}
}

static void crash_append_param_unavailable(struct crash_symbolized_frame *result,
					   const char *name)
{
	size_t offset;

	if (result == NULL || name == NULL || name[0] == '\0')
		return;
	offset = strlen(result->params_text);
	if (offset != 0)
		offset = crash_appendf(result->params_text,
				      sizeof(result->params_text), offset,
				      " ");
	offset = crash_appendf(result->params_text, sizeof(result->params_text),
			      offset, "%s=<unavailable>", name);
	result->has_params = offset != 0;
}

static void crash_append_param_value(struct crash_symbolized_frame *result,
				      const char *name, uint64_t value,
				      const char *location_name)
{
	size_t offset;

	if (result == NULL || name == NULL || name[0] == '\0')
		return;
	offset = strlen(result->params_text);
	if (offset != 0)
		offset = crash_appendf(result->params_text,
				      sizeof(result->params_text), offset,
				      " ");
	if (location_name != NULL && location_name[0] != '\0')
		offset = crash_appendf(result->params_text,
				      sizeof(result->params_text), offset,
				      "%s=0x%llx @%s", name,
				      (unsigned long long)value,
				      location_name);
	else
		offset = crash_appendf(result->params_text,
				      sizeof(result->params_text), offset,
				      "%s=0x%llx", name,
				      (unsigned long long)value);
	result->has_params = offset != 0;
}

static void crash_append_param_location(struct crash_symbolized_frame *result,
				 const char *name,
				 const char *location_name)
{
	size_t offset;

	if (result == NULL || name == NULL || name[0] == '\0' ||
	    location_name == NULL || location_name[0] == '\0')
		return;
	offset = strlen(result->params_text);
	if (offset != 0)
		offset = crash_appendf(result->params_text,
				      sizeof(result->params_text), offset,
				      " ");
	offset = crash_appendf(result->params_text, sizeof(result->params_text),
			      offset, "%s=<unavailable> @%s", name,
			      location_name);
	result->has_params = offset != 0;
}

static void crash_format_location_offset(char *buf, size_t buf_size,
				 const char *base, int64_t offset)
{
	if (buf == NULL || buf_size == 0)
		return;
	buf[0] = '\0';
	if (base == NULL || base[0] == '\0')
		return;
	if (offset == 0) {
		crash_copy_cstr(buf, buf_size, base);
		return;
	}
	if (offset > 0)
		(void)snprintf(buf, buf_size, "%s+0x%llx", base,
			       (unsigned long long)offset);
	else
		(void)snprintf(buf, buf_size, "%s-0x%llx", base,
			       (unsigned long long)(uint64_t)(-offset));
}

static uint64_t crash_frame_pointer_value(const struct crash_snapshot_record *record,
					 const struct crash_snapshot_frame *frame)
{
	if (frame != NULL && frame->frame_fp != 0)
		return frame->frame_fp;
	if (record != NULL && frame != NULL &&
	    (frame->frame_flags & CRASH_SNAPSHOT_FRAME_TOP) != 0)
		return record->fp;
	return 0;
}

static const char *crash_frame_pointer_name(const struct crash_snapshot_record *record)
{
	if (record == NULL)
		return "fp";
	switch (record->arch) {
	case CRASH_SNAPSHOT_ARCH_X86_64:
		return "rbp";
	case CRASH_SNAPSHOT_ARCH_AARCH64:
		return "x29";
	default:
		return "fp";
	}
}

static int crash_snapshot_read_word(const struct crash_snapshot_record *record,
				    uint64_t addr, uint8_t size,
				    uint64_t *value)
{
	uint64_t start;
	uint64_t end;
	uint64_t offset;
	uint64_t loaded = 0;

	if (value != NULL)
		*value = 0;
	if (record == NULL || value == NULL || size == 0 || size > sizeof(loaded) ||
	    (record->capture_flags & CRASH_SNAPSHOT_FLAG_STACK_WINDOW) == 0)
		return ETR_NOTEXIST;
	start = record->stack_window_start;
	end = start + record->stack_window_size;
	if (end < start || addr < start || addr + size > end)
		return ETR_NOTEXIST;
	offset = addr - start;
	memcpy(&loaded, record->stack_window + offset, size);
	*value = loaded;
	return ETR_OK;
}

static const char *crash_dwarf_reg_name(const struct crash_snapshot_record *record,
				Dwarf_Unsigned regno)
{
	static const char *const aarch64_names[] = {
		"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
		"x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
		"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
		"x24", "x25", "x26", "x27", "x28", "x29", "x30",
	};

	if (record == NULL)
		return NULL;
	switch (record->arch) {
	case CRASH_SNAPSHOT_ARCH_X86_64:
		switch (regno) {
		case 0:
			return "rax";
		case 1:
			return "rdx";
		case 2:
			return "rcx";
		case 3:
			return "rbx";
		case 4:
			return "rsi";
		case 5:
			return "rdi";
		case 6:
			return "rbp";
		case 7:
			return "rsp";
		case 8:
			return "r8";
		case 9:
			return "r9";
		case 10:
			return "r10";
		case 11:
			return "r11";
		case 12:
			return "r12";
		case 13:
			return "r13";
		case 14:
			return "r14";
		case 15:
			return "r15";
		case 16:
			return "rip";
		default:
			return NULL;
		}
	case CRASH_SNAPSHOT_ARCH_AARCH64:
		if (regno <= 30)
			return aarch64_names[regno];
		if (regno == 31)
			return "sp";
		return NULL;
	default:
		return NULL;
	}
}

static int crash_register_value_by_dwarf_reg(const struct crash_param_eval_context *ctx,
				     Dwarf_Unsigned regno,
				     uint64_t *value,
				     const char **location_name)
{
	const struct crash_snapshot_record *record;
	const struct crash_snapshot_frame *frame;
	uint64_t frame_fp;
	int top_frame;

	if (value != NULL)
		*value = 0;
	if (location_name != NULL)
		*location_name = NULL;
	if (ctx == NULL || ctx->record == NULL || ctx->frame == NULL)
		return ETR_INVAL;

	record = ctx->record;
	frame = ctx->frame;
	frame_fp = crash_frame_pointer_value(record, frame);
	top_frame = (frame->frame_flags & CRASH_SNAPSHOT_FRAME_TOP) != 0;
	if (location_name != NULL)
		*location_name = crash_dwarf_reg_name(record, regno);

	switch (record->arch) {
	case CRASH_SNAPSHOT_ARCH_X86_64:
		if (crash_record_has_full_regs(record) && top_frame) {
			switch (regno) {
			case 0:
				*value = record->registers.x86_64.rax;
				return ETR_OK;
			case 1:
				*value = record->registers.x86_64.rdx;
				return ETR_OK;
			case 2:
				*value = record->registers.x86_64.rcx;
				return ETR_OK;
			case 3:
				*value = record->registers.x86_64.rbx;
				return ETR_OK;
			case 4:
				*value = record->registers.x86_64.rsi;
				return ETR_OK;
			case 5:
				*value = record->registers.x86_64.rdi;
				return ETR_OK;
			case 6:
				*value = record->registers.x86_64.rbp;
				return ETR_OK;
			case 7:
				*value = record->registers.x86_64.rsp;
				return ETR_OK;
			case 8:
				*value = record->registers.x86_64.r8;
				return ETR_OK;
			case 9:
				*value = record->registers.x86_64.r9;
				return ETR_OK;
			case 10:
				*value = record->registers.x86_64.r10;
				return ETR_OK;
			case 11:
				*value = record->registers.x86_64.r11;
				return ETR_OK;
			case 12:
				*value = record->registers.x86_64.r12;
				return ETR_OK;
			case 13:
				*value = record->registers.x86_64.r13;
				return ETR_OK;
			case 14:
				*value = record->registers.x86_64.r14;
				return ETR_OK;
			case 15:
				*value = record->registers.x86_64.r15;
				return ETR_OK;
			case 16:
				*value = record->registers.x86_64.rip;
				return ETR_OK;
			default:
				break;
			}
		}
		if (top_frame) {
			switch (regno) {
			case 1:
				*value = record->args[2];
				return ETR_OK;
			case 2:
				*value = record->args[3];
				return ETR_OK;
			case 4:
				*value = record->args[1];
				return ETR_OK;
			case 5:
				*value = record->args[0];
				return ETR_OK;
			case 6:
				if (frame_fp != 0) {
					*value = frame_fp;
					return ETR_OK;
				}
				break;
			case 7:
				*value = record->sp;
				return ETR_OK;
			case 8:
				*value = record->args[4];
				return ETR_OK;
			case 9:
				*value = record->args[5];
				return ETR_OK;
			case 16:
				*value = record->ip;
				return ETR_OK;
			default:
				break;
			}
		}
		if (regno == 6 && frame_fp != 0) {
			*value = frame_fp;
			return ETR_OK;
		}
		return ETR_NOTEXIST;
	case CRASH_SNAPSHOT_ARCH_AARCH64:
		if (crash_record_has_full_regs(record) && top_frame) {
			if (regno <= 30) {
				*value = record->registers.aarch64.x[regno];
				return ETR_OK;
			}
			if (regno == 31) {
				*value = record->registers.aarch64.sp;
				return ETR_OK;
			}
		}
		if (top_frame) {
			if (regno < CRASH_SNAPSHOT_ARG_REGS) {
				*value = record->args[regno];
				return ETR_OK;
			}
			if (regno == 29 && frame_fp != 0) {
				*value = frame_fp;
				return ETR_OK;
			}
			if (regno == 30) {
				*value = record->lr;
				return ETR_OK;
			}
			if (regno == 31) {
				*value = record->sp;
				return ETR_OK;
			}
		}
		if (regno == 29 && frame_fp != 0) {
			*value = frame_fp;
			return ETR_OK;
		}
		return ETR_NOTEXIST;
	default:
		return ETR_NOTEXIST;
	}
}

static int64_t crash_dwarf_signed_operand(Dwarf_Small opcode,
					  Dwarf_Unsigned operand)
{
	if (opcode >= DW_OP_breg0 && opcode <= DW_OP_breg31)
		return (int64_t)(Dwarf_Signed)operand;
	switch (opcode) {
	case DW_OP_consts:
	case DW_OP_fbreg:
		return (int64_t)(Dwarf_Signed)operand;
	default:
		return (int64_t)operand;
	}
}

static int crash_follow_reference_die(Dwarf_Debug dbg, Dwarf_Die die,
				      Dwarf_Half attrnum,
				      Dwarf_Die *target_die,
				      Dwarf_Bool *target_is_info,
				      Dwarf_Error *errp)
{
	Dwarf_Attribute attr = 0;
	Dwarf_Off offset = 0;
	Dwarf_Bool is_info = 1;
	int rc;

	if (target_die != NULL)
		*target_die = 0;
	if (target_is_info != NULL)
		*target_is_info = 1;
	if (dbg == NULL || die == 0 || target_die == NULL)
		return ETR_INVAL;

	rc = dwarf_attr(die, attrnum, &attr, errp);
	if (rc != DW_DLV_OK)
		return ETR_NOTEXIST;
	rc = dwarf_global_formref_b(attr, &offset, &is_info, errp);
	dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
	if (rc != DW_DLV_OK)
		return ETR_NOTEXIST;
	rc = dwarf_offdie_b(dbg, offset, is_info, target_die, errp);
	if (rc != DW_DLV_OK) {
		if (target_die != NULL)
			*target_die = 0;
		return ETR_NOTEXIST;
	}
	if (target_is_info != NULL)
		*target_is_info = is_info;
	return ETR_OK;
}

static int crash_resolve_die_byte_size_recursive(Dwarf_Debug dbg, Dwarf_Die die,
					 Dwarf_Bool is_info,
					 uint8_t *size,
					 int depth,
					 Dwarf_Error *errp)
{
	Dwarf_Attribute attr = 0;
	Dwarf_Unsigned byte_size = 0;
	Dwarf_Die target = 0;
	Dwarf_Bool target_is_info = 1;
	int rc;

	if (size != NULL)
		*size = 0;
	if (dbg == NULL || die == 0 || size == NULL ||
	    depth >= CRASH_DWARF_REF_DEPTH_MAX)
		return ETR_INVAL;

	rc = dwarf_attr(die, DW_AT_byte_size, &attr, errp);
	if (rc == DW_DLV_OK) {
		rc = dwarf_formudata(attr, &byte_size, errp);
		dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
		if (rc == DW_DLV_OK && byte_size != 0) {
			*size = byte_size > UINT8_MAX ? UINT8_MAX : (uint8_t)byte_size;
			return ETR_OK;
		}
	}
	if (crash_follow_reference_die(dbg, die, DW_AT_type, &target,
				       &target_is_info, errp) == ETR_OK) {
		rc = crash_resolve_die_byte_size_recursive(dbg, target,
						       target_is_info,
						       size,
						       depth + 1,
						       errp);
		dwarf_dealloc(dbg, target, DW_DLA_DIE);
		if (rc == ETR_OK)
			return ETR_OK;
	}
	(void)is_info;
	return ETR_NOTEXIST;
}

static uint8_t crash_resolve_parameter_byte_size(Dwarf_Debug dbg,
					 Dwarf_Die param_die,
					 Dwarf_Bool param_is_info,
					 Dwarf_Error *errp)
{
	uint8_t size = (uint8_t)sizeof(uint64_t);
	uint8_t resolved = 0;

	if (dbg == NULL || param_die == 0)
		return size;
	if (crash_resolve_die_byte_size_recursive(dbg, param_die, param_is_info,
						 &resolved, 0,
						 errp) == ETR_OK &&
	    resolved != 0)
		return resolved;
	return size;
}

static int crash_copy_die_name_recursive(Dwarf_Debug dbg, Dwarf_Die die,
					 Dwarf_Bool is_info,
					 char *buf, size_t buf_size,
					 int depth,
					 Dwarf_Error *errp)
{
	Dwarf_Die target = 0;
	Dwarf_Bool target_is_info = 1;
	char *name = NULL;
	int rc;

	if (buf != NULL && buf_size != 0)
		buf[0] = '\0';
	if (dbg == NULL || die == 0 || buf == NULL || buf_size == 0 ||
	    depth >= CRASH_DWARF_REF_DEPTH_MAX)
		return ETR_NOTEXIST;

	rc = dwarf_die_text(die, DW_AT_name, &name, errp);
	if (rc == DW_DLV_OK && name != NULL && name[0] != '\0') {
		crash_copy_cstr(buf, buf_size, name);
		return ETR_OK;
	}
	rc = dwarf_die_text(die, DW_AT_linkage_name, &name, errp);
	if (rc == DW_DLV_OK && name != NULL && name[0] != '\0') {
		crash_copy_cstr(buf, buf_size, name);
		return ETR_OK;
	}
	rc = dwarf_die_text(die, DW_AT_MIPS_linkage_name, &name, errp);
	if (rc == DW_DLV_OK && name != NULL && name[0] != '\0') {
		crash_copy_cstr(buf, buf_size, name);
		return ETR_OK;
	}

	if (crash_follow_reference_die(dbg, die, DW_AT_abstract_origin, &target,
				       &target_is_info, errp) == ETR_OK) {
		rc = crash_copy_die_name_recursive(dbg, target, target_is_info, buf,
						  buf_size, depth + 1,
						  errp);
		dwarf_dealloc(dbg, target, DW_DLA_DIE);
		if (rc == ETR_OK)
			return ETR_OK;
	}
	if (crash_follow_reference_die(dbg, die, DW_AT_specification, &target,
				       &target_is_info, errp) == ETR_OK) {
		rc = crash_copy_die_name_recursive(dbg, target, target_is_info, buf,
						  buf_size, depth + 1,
						  errp);
		dwarf_dealloc(dbg, target, DW_DLA_DIE);
		if (rc == ETR_OK)
			return ETR_OK;
	}
	(void)is_info;
	return ETR_NOTEXIST;
}

static void crash_expr_stack_reset(struct crash_expr_stack_item *stack,
				   size_t stack_cap)
{
	size_t i;

	if (stack == NULL)
		return;
	for (i = 0; i < stack_cap; i++) {
		stack[i].value = 0;
		stack[i].location[0] = '\0';
		stack[i].has_value = false;
		stack[i].is_address = false;
		stack[i].has_location = false;
	}
}

static int crash_expr_stack_push(struct crash_expr_stack_item *stack,
				 size_t stack_cap,
				 size_t *stack_size,
				 const struct crash_expr_stack_item *item)
{
	if (stack == NULL || stack_size == NULL || item == NULL ||
	    *stack_size >= stack_cap)
		return ETR_INVAL;
	stack[*stack_size] = *item;
	(*stack_size)++;
	return ETR_OK;
}

static int crash_expr_stack_pop(struct crash_expr_stack_item *stack,
				 size_t *stack_size,
				 struct crash_expr_stack_item *item)
{
	if (stack == NULL || stack_size == NULL || item == NULL || *stack_size == 0)
		return ETR_NOTEXIST;
	*item = stack[*stack_size - 1];
	(*stack_size)--;
	return ETR_OK;
}

static void crash_expr_value_reset(struct crash_expr_value *value)
{
	if (value == NULL)
		return;
	value->value = 0;
	value->location[0] = '\0';
	value->byte_size = 0;
	value->has_value = false;
	value->is_address = false;
	value->has_location = false;
}

static int crash_init_param_eval_context(struct crash_param_eval_context *ctx,
					 const struct crash_snapshot_record *record,
					 const struct crash_snapshot_frame *frame,
					 uint64_t dwarf_pc)
{
	if (ctx == NULL || record == NULL || frame == NULL)
		return ETR_INVAL;
	memset(ctx, 0, sizeof(*ctx));
	ctx->record = record;
	ctx->frame = frame;
	ctx->frame_pc = crash_lookup_pc_for_frame(frame, frame->absolute_pc);
	ctx->pc = dwarf_pc != 0 ? dwarf_pc : ctx->frame_pc;
	return ETR_OK;
}

static int crash_compute_simple_cfa(struct crash_param_eval_context *ctx)
{
	uint64_t frame_fp;
	uint64_t cfa;

	if (ctx == NULL || ctx->record == NULL || ctx->frame == NULL)
		return ETR_INVAL;
	if (ctx->has_call_frame_cfa)
		return ETR_OK;
	frame_fp = crash_frame_pointer_value(ctx->record, ctx->frame);
	if (frame_fp == 0)
		return ETR_NOTEXIST;

	switch (ctx->record->arch) {
	case CRASH_SNAPSHOT_ARCH_X86_64:
		cfa = frame_fp + sizeof(uint64_t) * 2;
		break;
	case CRASH_SNAPSHOT_ARCH_AARCH64:
		cfa = frame_fp + sizeof(uint64_t) * 2;
		break;
	default:
		return ETR_NOTEXIST;
	}
	ctx->call_frame_cfa = cfa;
	crash_format_location_offset(ctx->call_frame_cfa_location,
				     sizeof(ctx->call_frame_cfa_location),
				     crash_frame_pointer_name(ctx->record),
				     (int64_t)(cfa - frame_fp));
	ctx->has_call_frame_cfa = true;
	return ETR_OK;
}

static int crash_load_stack_address(const struct crash_param_eval_context *ctx,
				   uint64_t addr,
				   struct crash_expr_value *out)
{
	uint64_t loaded = 0;
	uint8_t load_size;

	if (ctx == NULL || out == NULL)
		return ETR_INVAL;
	load_size = out->byte_size != 0 ? out->byte_size : (uint8_t)sizeof(uint64_t);
	if (load_size > sizeof(uint64_t))
		return ETR_NOTEXIST;
	if (crash_snapshot_read_word(ctx->record, addr, load_size, &loaded) != ETR_OK)
		return ETR_NOTEXIST;
	out->value = loaded;
	out->byte_size = load_size;
	out->has_value = true;
	out->is_address = false;
	if (!out->has_location || out->location[0] == '\0') {
		out->has_location = true;
		crash_format_location_offset(out->location, sizeof(out->location),
					     "mem", (int64_t)addr);
	}
	return ETR_OK;
}

static int crash_eval_locdesc(const struct crash_param_eval_context *ctx,
			      Dwarf_Locdesc_c locdesc,
			      Dwarf_Unsigned op_count,
			      bool load_memory,
			      struct crash_expr_value *out,
			      Dwarf_Error *errp)
{
	struct crash_expr_stack_item stack[CRASH_DWARF_EXPR_STACK_MAX];
	size_t stack_size = 0;
	Dwarf_Unsigned op_index;
	struct crash_expr_stack_item lhs = { 0 };
	uint8_t requested_size = 0;

	if (out != NULL) {
		requested_size = out->byte_size;
		crash_expr_value_reset(out);
		out->byte_size = requested_size;
	}
	if (ctx == NULL || out == NULL)
		return ETR_INVAL;

	crash_expr_stack_reset(stack, CRASH_DWARF_EXPR_STACK_MAX);
	for (op_index = 0; op_index < op_count; op_index++) {
		Dwarf_Small opcode = 0;
		Dwarf_Unsigned operand1 = 0;
		Dwarf_Unsigned operand2 = 0;
		Dwarf_Unsigned operand3 = 0;
		Dwarf_Unsigned branch_offset = 0;
		struct crash_expr_stack_item item;
		const char *reg_name = NULL;
		uint64_t reg_value = 0;
		int64_t signed_operand;

		if (dwarf_get_location_op_value_c(locdesc, op_index, &opcode,
						 &operand1, &operand2,
						 &operand3,
						 &branch_offset,
						 errp) != DW_DLV_OK)
			return ETR_NOTEXIST;
		(void)operand2;
		(void)operand3;
		(void)branch_offset;
		memset(&item, 0, sizeof(item));
		signed_operand = crash_dwarf_signed_operand(opcode, operand1);

		switch (opcode) {
		case DW_OP_reg0 ... DW_OP_reg31:
			if (crash_register_value_by_dwarf_reg(ctx,
						     (Dwarf_Unsigned)(opcode -
								      DW_OP_reg0),
						     &reg_value,
						     &reg_name) == ETR_OK) {
				item.value = reg_value;
				item.has_value = true;
			}
			if (reg_name != NULL && reg_name[0] != '\0') {
				crash_copy_cstr(item.location,
						sizeof(item.location), reg_name);
				item.has_location = true;
			}
			item.is_address = false;
			if (crash_expr_stack_push(stack,
						 CRASH_DWARF_EXPR_STACK_MAX,
						 &stack_size,
						 &item) != ETR_OK)
				return ETR_NOTEXIST;
			break;
		case DW_OP_breg0 ... DW_OP_breg31:
			if (crash_register_value_by_dwarf_reg(ctx,
						     (Dwarf_Unsigned)(opcode -
								      DW_OP_breg0),
						     &reg_value,
						     &reg_name) != ETR_OK)
				return ETR_NOTEXIST;
			item.value = reg_value + (uint64_t)signed_operand;
			item.has_value = true;
			item.is_address = true;
			item.has_location = true;
			crash_format_location_offset(item.location,
						sizeof(item.location),
						reg_name,
						signed_operand);
			if (crash_expr_stack_push(stack,
						 CRASH_DWARF_EXPR_STACK_MAX,
						 &stack_size,
						 &item) != ETR_OK)
				return ETR_NOTEXIST;
			break;
		case DW_OP_fbreg:
			if (!ctx->has_frame_base)
				return ETR_NOTEXIST;
			item.value = ctx->frame_base + (uint64_t)signed_operand;
			item.has_value = true;
			item.is_address = true;
			item.has_location = true;
			crash_format_location_offset(item.location,
						sizeof(item.location),
						ctx->frame_base_location,
						signed_operand);
			if (crash_expr_stack_push(stack,
						 CRASH_DWARF_EXPR_STACK_MAX,
						 &stack_size,
						 &item) != ETR_OK)
				return ETR_NOTEXIST;
			break;
		case DW_OP_call_frame_cfa:
			if (!ctx->has_call_frame_cfa)
				return ETR_NOTEXIST;
			item.value = ctx->call_frame_cfa;
			item.has_value = true;
			item.is_address = true;
			item.has_location = true;
			crash_copy_cstr(item.location, sizeof(item.location),
					ctx->call_frame_cfa_location);
			if (crash_expr_stack_push(stack,
						 CRASH_DWARF_EXPR_STACK_MAX,
						 &stack_size,
						 &item) != ETR_OK)
				return ETR_NOTEXIST;
			break;
		case DW_OP_plus_uconst:
			if (crash_expr_stack_pop(stack, &stack_size, &lhs) != ETR_OK ||
			    !lhs.has_value)
				return ETR_NOTEXIST;
			lhs.value += operand1;
			if (lhs.has_location) {
				char base_location[CRASH_PARAM_LOCATION_LEN];

				crash_copy_cstr(base_location, sizeof(base_location),
						lhs.location);
				crash_format_location_offset(lhs.location,
						    sizeof(lhs.location),
						    base_location,
						    (int64_t)operand1);
			}
			if (crash_expr_stack_push(stack,
						 CRASH_DWARF_EXPR_STACK_MAX,
						 &stack_size,
						 &lhs) != ETR_OK)
				return ETR_NOTEXIST;
			break;
		case DW_OP_consts:
		case DW_OP_constu:
			item.value = (uint64_t)signed_operand;
			item.has_value = true;
			item.is_address = false;
			if (crash_expr_stack_push(stack,
						 CRASH_DWARF_EXPR_STACK_MAX,
						 &stack_size,
						 &item) != ETR_OK)
				return ETR_NOTEXIST;
			break;
		case DW_OP_stack_value:
			if (crash_expr_stack_pop(stack, &stack_size, &lhs) != ETR_OK)
				return ETR_NOTEXIST;
			lhs.is_address = false;
			if (crash_expr_stack_push(stack,
						 CRASH_DWARF_EXPR_STACK_MAX,
						 &stack_size,
						 &lhs) != ETR_OK)
				return ETR_NOTEXIST;
			break;
		default:
			return ETR_NOTEXIST;
		}
	}

	if (crash_expr_stack_pop(stack, &stack_size, &lhs) != ETR_OK ||
	    stack_size != 0)
		return ETR_NOTEXIST;
	out->is_address = lhs.is_address;
	out->has_location = lhs.has_location;
	if (lhs.has_location)
		crash_copy_cstr(out->location, sizeof(out->location), lhs.location);
	if (!lhs.has_value)
		return out->has_location ? ETR_OK : ETR_NOTEXIST;
	out->value = lhs.value;
	out->has_value = true;
	if (out->is_address) {
		if (!load_memory)
			return ETR_OK;
		if (crash_load_stack_address(ctx, out->value, out) == ETR_OK)
			return ETR_OK;
		out->has_value = false;
		out->is_address = false;
		return out->has_location ? ETR_OK : ETR_NOTEXIST;
	}
	return ETR_OK;
}

static int crash_eval_location_attribute(const struct crash_param_eval_context *ctx,
					 Dwarf_Attribute attr,
					 bool load_memory,
					 struct crash_expr_value *out,
					 Dwarf_Error *errp)
{
	Dwarf_Loc_Head_c loc_head = 0;
	Dwarf_Unsigned loc_count = 0;
	unsigned int loc_kind = DW_LKIND_unknown;
	int rc;
	Dwarf_Unsigned entry_index;
	int ret = ETR_NOTEXIST;
	uint8_t requested_size = 0;

	if (out != NULL) {
		requested_size = out->byte_size;
		crash_expr_value_reset(out);
		out->byte_size = requested_size;
	}
	if (ctx == NULL || attr == 0 || out == NULL)
		return ETR_INVAL;

	rc = dwarf_get_loclist_c(attr, &loc_head, &loc_count, errp);
	if (rc != DW_DLV_OK || loc_head == 0 || loc_count == 0)
		return ETR_NOTEXIST;
	(void)dwarf_get_loclist_head_kind(loc_head, &loc_kind, errp);

	for (entry_index = 0; entry_index < loc_count; entry_index++) {
		Dwarf_Small lle_value = 0;
		Dwarf_Unsigned raw_low = 0;
		Dwarf_Unsigned raw_high = 0;
		Dwarf_Bool debug_addr_unavailable = 0;
		Dwarf_Addr lowpc = 0;
		Dwarf_Addr highpc = 0;
		Dwarf_Unsigned op_count = 0;
		Dwarf_Locdesc_c locdesc = 0;
		Dwarf_Small source = 0;
		Dwarf_Unsigned expr_offset = 0;
		Dwarf_Unsigned locdesc_offset = 0;
		int range_matches = 1;
		struct crash_expr_value value;

		crash_expr_value_reset(&value);
		value.byte_size = requested_size;
		rc = dwarf_get_locdesc_entry_d(loc_head, entry_index, &lle_value,
					      &raw_low, &raw_high,
					      &debug_addr_unavailable,
					      &lowpc, &highpc,
					      &op_count, &locdesc,
					      &source, &expr_offset,
					      &locdesc_offset, errp);
		if (rc != DW_DLV_OK)
			continue;
		(void)lle_value;
		(void)raw_low;
		(void)raw_high;
		(void)source;
		(void)expr_offset;
		(void)locdesc_offset;
		if (loc_kind != DW_LKIND_expression && !debug_addr_unavailable &&
		    highpc > lowpc)
			range_matches = ctx->pc >= lowpc && ctx->pc < highpc;
		if (!range_matches)
			continue;
		if (crash_eval_locdesc(ctx, locdesc, op_count, load_memory, &value,
				      errp) == ETR_OK) {
			*out = value;
			ret = ETR_OK;
			break;
		}
	}

	dwarf_dealloc_loc_head_c(loc_head);
	return ret;
}

static int crash_eval_die_location_recursive(Dwarf_Debug dbg, Dwarf_Die die,
					     Dwarf_Bool is_info,
					     Dwarf_Half attrnum,
					     struct crash_param_eval_context *ctx,
					     bool load_memory,
					     struct crash_expr_value *out,
					     int depth,
					     Dwarf_Error *errp)
{
	Dwarf_Attribute attr = 0;
	Dwarf_Die target = 0;
	Dwarf_Bool target_is_info = 1;
	int rc;
	uint8_t requested_size = 0;

	if (out != NULL) {
		requested_size = out->byte_size;
		crash_expr_value_reset(out);
		out->byte_size = requested_size;
	}
	if (dbg == NULL || die == 0 || ctx == NULL || out == NULL ||
	    depth >= CRASH_DWARF_REF_DEPTH_MAX)
		return ETR_INVAL;

	rc = dwarf_attr(die, attrnum, &attr, errp);
	if (rc == DW_DLV_OK) {
		rc = crash_eval_location_attribute(ctx, attr, load_memory, out,
						  errp);
		dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
		if (rc == ETR_OK)
			return ETR_OK;
	}
	if (crash_follow_reference_die(dbg, die, DW_AT_abstract_origin, &target,
				       &target_is_info, errp) == ETR_OK) {
		rc = crash_eval_die_location_recursive(dbg, target, target_is_info,
						      attrnum, ctx,
						      load_memory, out,
						      depth + 1,
						      errp);
		dwarf_dealloc(dbg, target, DW_DLA_DIE);
		if (rc == ETR_OK)
			return ETR_OK;
	}
	if (crash_follow_reference_die(dbg, die, DW_AT_specification, &target,
				       &target_is_info, errp) == ETR_OK) {
		rc = crash_eval_die_location_recursive(dbg, target, target_is_info,
						      attrnum, ctx,
						      load_memory, out,
						      depth + 1,
						      errp);
		dwarf_dealloc(dbg, target, DW_DLA_DIE);
		if (rc == ETR_OK)
			return ETR_OK;
	}
	(void)is_info;
	return ETR_NOTEXIST;
}

static int crash_prepare_frame_base(Dwarf_Debug dbg, Dwarf_Die die,
				    Dwarf_Bool is_info,
				    struct crash_param_eval_context *ctx,
				    Dwarf_Error *errp)
{
	struct crash_expr_value value;
	uint64_t frame_fp;
	int rc;

	if (ctx == NULL || ctx->record == NULL || ctx->frame == NULL)
		return ETR_INVAL;
	if (ctx->has_frame_base)
		return ETR_OK;

	crash_expr_value_reset(&value);
	rc = crash_eval_die_location_recursive(dbg, die, is_info,
					      DW_AT_frame_base, ctx,
					      false, &value, 0, errp);
	if (rc == ETR_OK && value.has_value) {
		ctx->frame_base = value.value;
		ctx->has_frame_base = true;
		if (value.has_location)
			crash_copy_cstr(ctx->frame_base_location,
						sizeof(ctx->frame_base_location),
						value.location);
		else
			crash_copy_cstr(ctx->frame_base_location,
						sizeof(ctx->frame_base_location),
						"frame-base");
		return ETR_OK;
	}

	frame_fp = crash_frame_pointer_value(ctx->record, ctx->frame);
	if (frame_fp == 0)
		return ETR_NOTEXIST;
	ctx->frame_base = frame_fp;
	ctx->has_frame_base = true;
	crash_copy_cstr(ctx->frame_base_location,
			sizeof(ctx->frame_base_location),
			crash_frame_pointer_name(ctx->record));
	return ETR_OK;
}

static int crash_param_from_expr_value(const struct crash_expr_value *expr,
				      struct crash_param_value *param)
{
	if (param != NULL) {
		param->value = 0;
		param->location[0] = '\0';
		param->byte_size = 0;
		param->has_value = false;
		param->has_location = false;
	}
	if (expr == NULL || param == NULL)
		return ETR_INVAL;
	if (expr->has_value) {
		param->value = expr->value;
		param->byte_size = expr->byte_size;
		param->has_value = true;
	}
	if (expr->has_location && expr->location[0] != '\0') {
		crash_copy_cstr(param->location, sizeof(param->location),
				expr->location);
		param->has_location = true;
	}
	return param->has_value || param->has_location ? ETR_OK : ETR_NOTEXIST;
}

static int crash_recover_parameter_value(Dwarf_Debug dbg, Dwarf_Die subprogram_die,
					 Dwarf_Bool subprogram_is_info,
					 Dwarf_Die param_die,
					 Dwarf_Bool param_is_info,
					 struct crash_param_eval_context *ctx,
					 struct crash_param_value *param,
					 Dwarf_Error *errp)
{
	struct crash_expr_value expr;
	int rc;

	if (param != NULL) {
		param->value = 0;
		param->location[0] = '\0';
		param->byte_size = 0;
		param->has_value = false;
		param->has_location = false;
	}
	if (dbg == NULL || param_die == 0 || ctx == NULL || param == NULL)
		return ETR_INVAL;

	(void)crash_compute_simple_cfa(ctx);
	if (subprogram_die != 0)
		(void)crash_prepare_frame_base(dbg, subprogram_die, subprogram_is_info,
					      ctx, errp);
	crash_expr_value_reset(&expr);
	expr.byte_size = crash_resolve_parameter_byte_size(dbg, param_die,
						 param_is_info, errp);
	rc = crash_eval_die_location_recursive(dbg, param_die, param_is_info,
					      DW_AT_location, ctx,
					      true, &expr, 0, errp);
	if (rc != ETR_OK)
		return ETR_NOTEXIST;
	return crash_param_from_expr_value(&expr, param);
}


static uint32_t crash_collect_direct_formal_parameters(Dwarf_Debug dbg,
					   Dwarf_Die subprogram_die,
					   Dwarf_Bool subprogram_is_info,
					   Dwarf_Die params_die,
					   Dwarf_Bool params_is_info,
					   const struct crash_snapshot_record *record,
					   const struct crash_snapshot_frame *frame,
					   struct crash_param_eval_context *eval_ctx,
					   int have_eval_ctx,
					   uint32_t *param_index,
					   struct crash_symbolized_frame *result,
					   Dwarf_Error *errp)
{
	Dwarf_Die child = 0;
	int rc;
	uint32_t collected = 0;

	if (dbg == NULL || subprogram_die == 0 || params_die == 0 || record == NULL ||
	    frame == NULL || param_index == NULL || result == NULL)
		return 0;

	rc = dwarf_child(params_die, &child, errp);
	if (rc != DW_DLV_OK)
		return 0;

	for (;;) {
		Dwarf_Die sibling = 0;
		Dwarf_Half tag = 0;
		char fallback_name[CRASH_PARAM_NAME_LEN];
		char param_name_buf[CRASH_PARAM_NAME_LEN];
		const char *param_name = NULL;
		struct crash_param_value recovered;
		uint64_t abi_value = 0;
		const char *abi_location_name = NULL;

		memset(&recovered, 0, sizeof(recovered));
		if (dwarf_tag(child, &tag, errp) == DW_DLV_OK &&
		    tag == DW_TAG_formal_parameter) {
			if (crash_copy_die_name_recursive(dbg, child, params_is_info,
							 param_name_buf,
							 sizeof(param_name_buf), 0,
							 errp) == ETR_OK &&
			    param_name_buf[0] != '\0') {
				param_name = param_name_buf;
			} else {
				(void)snprintf(fallback_name, sizeof(fallback_name), "arg%u",
					       *param_index);
				param_name = fallback_name;
			}
			if (have_eval_ctx &&
			    crash_recover_parameter_value(dbg, subprogram_die,
						   subprogram_is_info, child,
						   params_is_info, eval_ctx,
						   &recovered,
						   errp) == ETR_OK) {
				if (recovered.has_value) {
					crash_append_param_value(result, param_name,
							 recovered.value,
							 recovered.has_location ?
							 recovered.location : NULL);
				} else if (recovered.has_location) {
					crash_append_param_location(result, param_name,
							    recovered.location);
				} else {
					crash_append_param_unavailable(result, param_name);
				}
			} else if (crash_top_frame_abi_value(record, frame, *param_index,
						    &abi_value,
						    &abi_location_name) == ETR_OK) {
				crash_append_param_value(result, param_name, abi_value,
						      abi_location_name);
			} else {
				crash_append_param_unavailable(result, param_name);
			}
			(*param_index)++;
			collected++;
		}
		rc = dwarf_siblingof_b(dbg, child, params_is_info, &sibling, errp);
		dwarf_dealloc(dbg, child, DW_DLA_DIE);
		if (rc != DW_DLV_OK)
			break;
		child = sibling;
	}
	return collected;
}

static uint32_t crash_collect_formal_parameters_recursive(Dwarf_Debug dbg,
					      Dwarf_Die subprogram_die,
					      Dwarf_Bool subprogram_is_info,
					      Dwarf_Die params_die,
					      Dwarf_Bool params_is_info,
					      const struct crash_snapshot_record *record,
					      const struct crash_snapshot_frame *frame,
					      struct crash_param_eval_context *eval_ctx,
					      int have_eval_ctx,
					      uint32_t *param_index,
					      struct crash_symbolized_frame *result,
					      int depth,
					      Dwarf_Error *errp)
{
	Dwarf_Die target = 0;
	Dwarf_Bool target_is_info = 1;
	uint32_t collected;

	if (dbg == NULL || subprogram_die == 0 || params_die == 0 || record == NULL ||
	    frame == NULL || param_index == NULL || result == NULL ||
	    depth >= CRASH_DWARF_REF_DEPTH_MAX)
		return 0;

	collected = crash_collect_direct_formal_parameters(dbg, subprogram_die,
							     subprogram_is_info,
							     params_die,
							     params_is_info,
							     record, frame,
							     eval_ctx,
							     have_eval_ctx,
							     param_index,
							     result, errp);
	if (collected != 0)
		return collected;

	if (crash_follow_reference_die(dbg, params_die, DW_AT_abstract_origin,
				       &target, &target_is_info,
				       errp) == ETR_OK) {
		collected = crash_collect_formal_parameters_recursive(dbg,
							     subprogram_die,
							     subprogram_is_info,
							     target,
							     target_is_info,
							     record,
							     frame,
							     eval_ctx,
							     have_eval_ctx,
							     param_index,
							     result,
							     depth + 1,
							     errp);
		dwarf_dealloc(dbg, target, DW_DLA_DIE);
		if (collected != 0)
			return collected;
	}
	if (crash_follow_reference_die(dbg, params_die, DW_AT_specification,
				       &target, &target_is_info,
				       errp) == ETR_OK) {
		collected = crash_collect_formal_parameters_recursive(dbg,
							     subprogram_die,
							     subprogram_is_info,
							     target,
							     target_is_info,
							     record,
							     frame,
							     eval_ctx,
							     have_eval_ctx,
							     param_index,
							     result,
							     depth + 1,
							     errp);
		dwarf_dealloc(dbg, target, DW_DLA_DIE);
		if (collected != 0)
			return collected;
	}
	return 0;
}

static void crash_collect_formal_parameters(Dwarf_Debug dbg, Dwarf_Die die,
					   Dwarf_Bool is_info,
					   const struct crash_snapshot_record *record,
					   const struct crash_snapshot_frame *frame,
					   uint64_t dwarf_pc,
					   struct crash_symbolized_frame *result,
					   Dwarf_Error *errp)
{
	struct crash_param_eval_context eval_ctx;
	int have_eval_ctx = 0;
	uint32_t param_index = 0;

	if (dbg == NULL || die == 0 || record == NULL || frame == NULL ||
	    result == NULL)
		return;

	if (crash_init_param_eval_context(&eval_ctx, record, frame, dwarf_pc) == ETR_OK)
		have_eval_ctx = 1;

	(void)crash_collect_formal_parameters_recursive(dbg, die, is_info, die,
						     is_info, record, frame,
						     &eval_ctx, have_eval_ctx,
						     &param_index, result, 0,
						     errp);
}

static int crash_die_pc_matches_range(uint64_t dwarf_pc, uint64_t start,
				       uint64_t end,
				       uint64_t *matched_start,
				       uint64_t *matched_end)
{
	if (start >= end)
		return 0;
	if (dwarf_pc < start || dwarf_pc >= end)
		return 0;
	if (matched_start != NULL)
		*matched_start = start;
	if (matched_end != NULL)
		*matched_end = end;
	return 1;
}

static int crash_read_die_low_pc(Dwarf_Die die, uint64_t *low_pc,
				 Dwarf_Error *errp)
{
	Dwarf_Addr addr = 0;

	if (low_pc != NULL)
		*low_pc = 0;
	if (die == 0 || low_pc == NULL)
		return ETR_INVAL;
	if (dwarf_lowpc(die, &addr, errp) != DW_DLV_OK)
		return ETR_NOTEXIST;
	*low_pc = (uint64_t)addr;
	return ETR_OK;
}

static int crash_get_attr_form_class(Dwarf_Die die, Dwarf_Attribute attr,
				     Dwarf_Half attrnum,
				     Dwarf_Half *form_out,
				     enum Dwarf_Form_Class *class_out,
				     Dwarf_Error *errp)
{
	Dwarf_Half version = 0;
	Dwarf_Half offset_size = 0;
	Dwarf_Half form = 0;
	int rc;

	if (form_out != NULL)
		*form_out = 0;
	if (class_out != NULL)
		*class_out = DW_FORM_CLASS_UNKNOWN;
	if (die == 0 || attr == 0)
		return ETR_INVAL;

	rc = dwarf_whatform(attr, &form, errp);
	if (rc != DW_DLV_OK)
		return ETR_NOTEXIST;
	rc = dwarf_get_version_of_die(die, &version, &offset_size);
	if (rc != DW_DLV_OK)
		return ETR_NOTEXIST;
	if (form_out != NULL)
		*form_out = form;
	if (class_out != NULL)
		*class_out = dwarf_get_form_class(version, attrnum, offset_size,
						 form);
	return ETR_OK;
}

static int crash_die_low_high_pc_contains_pc(Dwarf_Die die, uint64_t dwarf_pc,
					     int *had_coverage,
					     uint64_t *matched_start,
					     uint64_t *matched_end,
					     Dwarf_Error *errp)
{
	Dwarf_Addr low_pc = 0;
	Dwarf_Addr high_pc = 0;
	Dwarf_Half highpc_form = 0;
	enum Dwarf_Form_Class highpc_class = DW_FORM_CLASS_UNKNOWN;
	int rc;

	if (had_coverage != NULL)
		*had_coverage = 0;
	if (die == 0)
		return 0;

	rc = dwarf_lowpc(die, &low_pc, errp);
	if (rc != DW_DLV_OK)
		return 0;
	rc = dwarf_highpc_b(die, &high_pc, &highpc_form, &highpc_class, errp);
	if (rc != DW_DLV_OK)
		return 0;
	if (had_coverage != NULL)
		*had_coverage = 1;
	if (highpc_class == DW_FORM_CLASS_CONSTANT)
		high_pc += low_pc;
	return crash_die_pc_matches_range(dwarf_pc, (uint64_t)low_pc,
					  (uint64_t)high_pc,
					  matched_start, matched_end);
}

static int crash_die_ranges_contains_pc_classic(Dwarf_Debug dbg, Dwarf_Die die,
					Dwarf_Attribute ranges_attr,
					uint64_t dwarf_pc,
					uint64_t cu_base,
					int have_cu_base,
					uint64_t *matched_start,
					uint64_t *matched_end,
					Dwarf_Error *errp)
{
	Dwarf_Ranges *ranges = 0;
	Dwarf_Signed rangecount = 0;
	Dwarf_Unsigned range_offset = 0;
	Dwarf_Unsigned bytecount = 0;
	Dwarf_Off realoffset = 0;
	Dwarf_Addr low_pc = 0;
	uint64_t base = 0;
	int have_base = have_cu_base;
	int rc;
	Dwarf_Signed i;
	int found = 0;

	if (dbg == NULL || die == 0 || ranges_attr == 0)
		return 0;
	if (dwarf_lowpc(die, &low_pc, errp) == DW_DLV_OK) {
		base = (uint64_t)low_pc;
		have_base = 1;
	} else if (have_cu_base) {
		base = cu_base;
	}
	if (dwarf_formudata(ranges_attr, &range_offset, errp) != DW_DLV_OK)
		return 0;
	rc = dwarf_get_ranges_b(dbg, (Dwarf_Off)range_offset, die, &realoffset,
				&ranges, &rangecount, &bytecount, errp);
	if (rc != DW_DLV_OK)
		return 0;
	(void)realoffset;
	(void)bytecount;

	for (i = 0; i < rangecount; i++) {
		switch (ranges[i].dwr_type) {
		case DW_RANGES_ADDRESS_SELECTION:
			base = (uint64_t)ranges[i].dwr_addr2;
			have_base = 1;
			break;
		case DW_RANGES_ENTRY:
			if (have_base) {
				uint64_t start = base + (uint64_t)ranges[i].dwr_addr1;
				uint64_t end = base + (uint64_t)ranges[i].dwr_addr2;

				if (start >= base && end >= base &&
				    crash_die_pc_matches_range(dwarf_pc, start, end,
							     matched_start,
							     matched_end)) {
					found = 1;
					goto out;
				}
			}
			break;
		case DW_RANGES_END:
			goto out;
		default:
			break;
		}
	}

out:
	if (ranges != 0)
		dwarf_dealloc_ranges(dbg, ranges, rangecount);
	return found;
}

static int crash_die_ranges_contains_pc_rnglists(Dwarf_Attribute ranges_attr,
					 Dwarf_Half ranges_form,
					 uint64_t dwarf_pc,
					 uint64_t *matched_start,
					 uint64_t *matched_end,
					 Dwarf_Error *errp)
{
	Dwarf_Rnglists_Head head = 0;
	Dwarf_Unsigned range_value = 0;
	Dwarf_Unsigned entry_count = 0;
	Dwarf_Unsigned global_offset = 0;
	Dwarf_Unsigned i;
	int found = 0;

	if (ranges_attr == 0)
		return 0;
	if (dwarf_formudata(ranges_attr, &range_value, errp) != DW_DLV_OK)
		return 0;
	if (dwarf_rnglists_get_rle_head(ranges_attr, ranges_form, range_value,
					&head, &entry_count,
					&global_offset, errp) != DW_DLV_OK)
		return 0;
	(void)global_offset;

	for (i = 0; i < entry_count; i++) {
		unsigned int entrylen = 0;
		unsigned int rle_value = 0;
		Dwarf_Unsigned raw1 = 0;
		Dwarf_Unsigned raw2 = 0;
		Dwarf_Unsigned cooked1 = 0;
		Dwarf_Unsigned cooked2 = 0;
		Dwarf_Bool debug_addr_unavailable = 0;

		if (dwarf_get_rnglists_entry_fields_a(head, i, &entrylen,
						     &rle_value, &raw1,
						     &raw2,
						     &debug_addr_unavailable,
						     &cooked1, &cooked2,
						     errp) != DW_DLV_OK)
			continue;
		(void)entrylen;
		(void)raw1;
		(void)raw2;
		if (debug_addr_unavailable)
			continue;
		switch (rle_value) {
		case DW_RLE_offset_pair:
		case DW_RLE_startx_endx:
		case DW_RLE_startx_length:
		case DW_RLE_start_end:
		case DW_RLE_start_length:
			if (crash_die_pc_matches_range(dwarf_pc, (uint64_t)cooked1,
						      (uint64_t)cooked2,
						      matched_start,
						      matched_end)) {
				found = 1;
				goto out;
			}
			break;
		case DW_RLE_end_of_list:
			goto out;
		default:
			break;
		}
	}

out:
	if (head != 0)
		dwarf_dealloc_rnglists_head(head);
	return found;
}

static int crash_die_contains_pc(Dwarf_Debug dbg, Dwarf_Die die,
				 uint64_t dwarf_pc,
				 uint64_t cu_base,
				 int have_cu_base,
				 int *had_coverage,
				 uint64_t *matched_start,
				 uint64_t *matched_end,
				 Dwarf_Error *errp)
{
	Dwarf_Attribute ranges_attr = 0;
	Dwarf_Half ranges_form = 0;
	enum Dwarf_Form_Class ranges_class = DW_FORM_CLASS_UNKNOWN;
	int had_pc_coverage = 0;
	int found = 0;

	if (had_coverage != NULL)
		*had_coverage = 0;
	if (matched_start != NULL)
		*matched_start = 0;
	if (matched_end != NULL)
		*matched_end = 0;
	if (dbg == NULL || die == 0)
		return 0;
	if (crash_die_low_high_pc_contains_pc(die, dwarf_pc, &had_pc_coverage,
					       matched_start,
					       matched_end, errp)) {
		if (had_coverage != NULL)
			*had_coverage = 1;
		return 1;
	}
	if (had_pc_coverage) {
		if (had_coverage != NULL)
			*had_coverage = 1;
		return 0;
	}
	if (dwarf_attr(die, DW_AT_ranges, &ranges_attr, errp) != DW_DLV_OK)
		return 0;
	if (had_coverage != NULL)
		*had_coverage = 1;
	if (crash_get_attr_form_class(die, ranges_attr, DW_AT_ranges,
				     &ranges_form, &ranges_class,
				     errp) != ETR_OK)
		goto out;
	switch (ranges_class) {
	case DW_FORM_CLASS_RANGELISTPTR:
		found = crash_die_ranges_contains_pc_classic(dbg, die, ranges_attr,
						     dwarf_pc, cu_base,
						     have_cu_base,
						     matched_start,
						     matched_end,
						     errp);
		break;
	case DW_FORM_CLASS_RNGLIST:
	case DW_FORM_CLASS_RNGLISTSPTR:
		found = crash_die_ranges_contains_pc_rnglists(ranges_attr,
						      ranges_form,
						      dwarf_pc,
						      matched_start,
						      matched_end,
						      errp);
		break;
	default:
		break;
	}

out:
	dwarf_dealloc(dbg, ranges_attr, DW_DLA_ATTR);
	return found;
}

static int crash_subprogram_name_matches_symbol(Dwarf_Debug dbg, Dwarf_Die die,
					 Dwarf_Bool is_info,
					 const struct crash_symbolized_frame *result,
					 Dwarf_Error *errp)
{
	char die_name[CRASH_SYMBOL_NAME_LEN];

	if (dbg == NULL || die == 0 || result == NULL || !result->has_symbol ||
	    result->symbol_name[0] == '\0')
		return 0;
	if (crash_copy_die_name_recursive(dbg, die, is_info, die_name,
					 sizeof(die_name), 0,
					 errp) != ETR_OK ||
	    die_name[0] == '\0')
		return 0;
	return crash_symbol_names_match(die_name, result->symbol_name);
}

static int crash_subprogram_matches_frame(Dwarf_Debug dbg, Dwarf_Die die,
					  Dwarf_Bool is_info,
					  uint64_t dwarf_pc,
					  uint64_t cu_base,
					  int have_cu_base,
					  const struct crash_symbolized_frame *result,
					  Dwarf_Error *errp)
{
	int had_coverage = 0;

	if (dbg == NULL || die == 0 || result == NULL)
		return 0;
	if (crash_die_contains_pc(dbg, die, dwarf_pc, cu_base, have_cu_base,
				      &had_coverage, NULL, NULL, errp))
		return 1;
	if (had_coverage)
		return 0;
	return crash_subprogram_name_matches_symbol(dbg, die, is_info, result,
					     errp);
}

static int crash_symbolize_params_in_die(Dwarf_Debug dbg, Dwarf_Die die,
					 Dwarf_Bool is_info,
					 const struct crash_snapshot_record *record,
					 const struct crash_snapshot_frame *frame,
					 uint64_t dwarf_pc,
					 uint64_t cu_base,
					 int have_cu_base,
					 struct crash_symbolized_frame *result,
					 Dwarf_Error *errp)
{
	Dwarf_Half tag = 0;
	int rc;
	Dwarf_Die child = 0;

	if (dbg == NULL || die == 0 || result == NULL)
		return 0;

	rc = dwarf_tag(die, &tag, errp);
	if (rc != DW_DLV_OK)
		return 0;
	if (tag == DW_TAG_subprogram &&
	    crash_subprogram_matches_frame(dbg, die, is_info, dwarf_pc, cu_base,
					     have_cu_base, result,
					     errp)) {
		size_t params_len_before = strlen(result->params_text);

		crash_collect_formal_parameters(dbg, die, is_info, record, frame,
					       dwarf_pc, result, errp);
		if (strlen(result->params_text) != params_len_before)
			return 1;
	}

	rc = dwarf_child(die, &child, errp);
	if (rc == DW_DLV_OK) {
		for (;;) {
			Dwarf_Die sibling = 0;
			int found;

			found = crash_symbolize_params_in_die(dbg, child, is_info,
						      record, frame,
						      dwarf_pc,
						      cu_base,
						      have_cu_base,
						      result, errp);
			if (found) {
				dwarf_dealloc(dbg, child, DW_DLA_DIE);
				return 1;
			}
			rc = dwarf_siblingof_b(dbg, child, is_info, &sibling, errp);
			dwarf_dealloc(dbg, child, DW_DLA_DIE);
			if (rc != DW_DLV_OK)
				break;
			child = sibling;
		}
	}
	return 0;
}

static int crash_symbolize_dwarf_params(const char *path,
					const struct crash_snapshot_record *record,
					const struct crash_snapshot_frame *frame,
					struct crash_symbolized_frame *result)
{
	Dwarf_Debug dbg = 0;
	Dwarf_Error err = 0;
	Dwarf_Bool is_info = 1;
	int fd = -1;
	int rc;
	int found = 0;

	if (path == NULL || path[0] == '\0' || record == NULL || frame == NULL ||
	    result == NULL || !result->has_elf_vaddr)
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
		uint64_t cu_base = 0;
		int have_cu_base = 0;

		rc = dwarf_next_cu_header_d(dbg, is_info, NULL, NULL, NULL,
					    NULL, NULL, NULL, NULL, NULL, NULL,
					    NULL, &err);
		if (rc != DW_DLV_OK)
			break;
		rc = dwarf_siblingof_b(dbg, no_die, is_info, &cu_die, &err);
		if (rc != DW_DLV_OK)
			continue;
		if (crash_read_die_low_pc(cu_die, &cu_base, &err) == ETR_OK)
			have_cu_base = 1;
		found = crash_symbolize_params_in_die(dbg, cu_die, is_info, record,
						     frame, result->elf_vaddr,
						     cu_base, have_cu_base,
						     result, &err);
		dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
		if (found)
			break;
	}

	if (err != 0)
		dwarf_dealloc_error(dbg, err);
	(void)dwarf_finish(dbg);
	close(fd);
	return found && result->has_params ? ETR_OK : ETR_NOTEXIST;
}

/*
 * Walk a DIE subtree looking for a subprogram range that contains the target
 * address. When found, DWARF can provide a better function name than stripped
 * or incomplete ELF symbols.
 */
static void crash_symbolize_line_in_die(Dwarf_Debug dbg, Dwarf_Die die,
					uint64_t cu_base,
					int have_cu_base,
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
		uint64_t matched_start = 0;
		uint64_t matched_end = 0;
		int had_coverage = 0;

		if (crash_die_contains_pc(dbg, die, result->elf_vaddr, cu_base,
					 have_cu_base, &had_coverage,
					 &matched_start, &matched_end,
					 errp)) {
			char *name = NULL;

			if (!result->has_symbol &&
			    dwarf_diename(die, &name, errp) == DW_DLV_OK) {
				crash_set_symbol_name(result, name, matched_start,
						      matched_end - matched_start);
				if (name != NULL)
					dwarf_dealloc(dbg, name, DW_DLA_STRING);
			}
		}
	}

	rc = dwarf_child(die, &child, errp);
	if (rc == DW_DLV_OK) {
		Dwarf_Die current = child;

		for (;;) {
			Dwarf_Die sibling = 0;

			crash_symbolize_line_in_die(dbg, current, cu_base, have_cu_base,
						  result, errp);
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
		uint64_t cu_base = 0;
		int have_cu_base = 0;

		rc = dwarf_next_cu_header_d(dbg, is_info, NULL, NULL, NULL,
					    NULL, NULL, NULL, NULL, NULL, NULL,
					    NULL, &err);
		if (rc != DW_DLV_OK)
			break;
		rc = dwarf_siblingof_b(dbg, no_die, is_info, &cu_die, &err);
		if (rc != DW_DLV_OK)
			continue;

		if (crash_read_die_low_pc(cu_die, &cu_base, &err) == ETR_OK)
			have_cu_base = 1;
		crash_symbolize_line_in_die(dbg, cu_die, cu_base, have_cu_base,
					      result, &err);
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

	ret = crash_symbolize_prepare_vaddr(elf, frame, result);
	if (ret != ETR_OK)
		goto out;

	if (crash_find_debug_image(result->module, debug_path,
				   sizeof(debug_path)) == ETR_OK &&
	    openelf(debug_path, &debug_elf, &debug_fd) == 0) {
		(void)crash_symbolize_elf_symbols(debug_elf, result);
		(void)crash_symbolize_dwarf_lines(debug_path, result);
		(void)crash_symbolize_dwarf_params(debug_path, record, frame,
					      result);
	}
	if (!result->has_symbol)
		(void)crash_symbolize_elf_symbols(elf, result);
	if (!result->has_line)
		(void)crash_symbolize_dwarf_lines(result->module->path, result);
	if (!result->has_params)
		(void)crash_symbolize_dwarf_params(result->module->path, record,
					      frame, result);
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
 * recovered register block and the raw top-frame ABI argument registers are
 * logged immediately after the summary so the main headline remains
 * grep-friendly.
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

static int crash_record_has_full_regs(const struct crash_snapshot_record *record)
{
	return record != NULL &&
	    (record->capture_flags & CRASH_SNAPSHOT_FLAG_FULL_REGS) != 0;
}

/*
 * Emit the recovered top-frame general-purpose register block.
 *
 * v4 snapshots persist a richer register set than older records. When Stage 2
 * is consuming an upgraded v2/v3 record, keep the log honest by marking it as
 * partial and only printing the fields that older formats actually captured.
 */
static void crash_log_registers(const struct crash_snapshot_record *record)
{
	if (record == NULL)
		return;

	switch (record->arch) {
	case CRASH_SNAPSHOT_ARCH_X86_64:
		if (crash_record_has_full_regs(record)) {
			ebpf_info
			    ("Recovered crash registers: rip=0x%llx rsp=0x%llx rbp=0x%llx eflags=0x%llx\n",
			     (unsigned long long)record->registers.x86_64.rip,
			     (unsigned long long)record->registers.x86_64.rsp,
			     (unsigned long long)record->registers.x86_64.rbp,
			     (unsigned long long)record->registers.x86_64.eflags);
			ebpf_info
			    ("Recovered crash registers: rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx rsi=0x%llx rdi=0x%llx\n",
			     (unsigned long long)record->registers.x86_64.rax,
			     (unsigned long long)record->registers.x86_64.rbx,
			     (unsigned long long)record->registers.x86_64.rcx,
			     (unsigned long long)record->registers.x86_64.rdx,
			     (unsigned long long)record->registers.x86_64.rsi,
			     (unsigned long long)record->registers.x86_64.rdi);
			ebpf_info
			    ("Recovered crash registers: r8=0x%llx r9=0x%llx r10=0x%llx r11=0x%llx r12=0x%llx r13=0x%llx r14=0x%llx r15=0x%llx\n",
			     (unsigned long long)record->registers.x86_64.r8,
			     (unsigned long long)record->registers.x86_64.r9,
			     (unsigned long long)record->registers.x86_64.r10,
			     (unsigned long long)record->registers.x86_64.r11,
			     (unsigned long long)record->registers.x86_64.r12,
			     (unsigned long long)record->registers.x86_64.r13,
			     (unsigned long long)record->registers.x86_64.r14,
			     (unsigned long long)record->registers.x86_64.r15);
			return;
		}
		ebpf_info
		    ("Recovered crash registers (partial): rip=0x%llx rsp=0x%llx rbp=0x%llx rdi=0x%llx rsi=0x%llx rdx=0x%llx rcx=0x%llx r8=0x%llx r9=0x%llx\n",
		     (unsigned long long)record->ip,
		     (unsigned long long)record->sp,
		     (unsigned long long)record->fp,
		     (unsigned long long)record->args[0],
		     (unsigned long long)record->args[1],
		     (unsigned long long)record->args[2],
		     (unsigned long long)record->args[3],
		     (unsigned long long)record->args[4],
		     (unsigned long long)record->args[5]);
		return;
	case CRASH_SNAPSHOT_ARCH_AARCH64:
		if (crash_record_has_full_regs(record)) {
			ebpf_info
			    ("Recovered crash registers: pc=0x%llx sp=0x%llx x29=0x%llx x30=0x%llx pstate=0x%llx\n",
			     (unsigned long long)record->registers.aarch64.pc,
			     (unsigned long long)record->registers.aarch64.sp,
			     (unsigned long long)record->registers.aarch64.x[29],
			     (unsigned long long)record->registers.aarch64.x[30],
			     (unsigned long long)record->registers.aarch64.pstate);
			ebpf_info
			    ("Recovered crash registers: x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx x4=0x%llx x5=0x%llx x6=0x%llx x7=0x%llx\n",
			     (unsigned long long)record->registers.aarch64.x[0],
			     (unsigned long long)record->registers.aarch64.x[1],
			     (unsigned long long)record->registers.aarch64.x[2],
			     (unsigned long long)record->registers.aarch64.x[3],
			     (unsigned long long)record->registers.aarch64.x[4],
			     (unsigned long long)record->registers.aarch64.x[5],
			     (unsigned long long)record->registers.aarch64.x[6],
			     (unsigned long long)record->registers.aarch64.x[7]);
			ebpf_info
			    ("Recovered crash registers: x8=0x%llx x9=0x%llx x10=0x%llx x11=0x%llx x12=0x%llx x13=0x%llx x14=0x%llx x15=0x%llx\n",
			     (unsigned long long)record->registers.aarch64.x[8],
			     (unsigned long long)record->registers.aarch64.x[9],
			     (unsigned long long)record->registers.aarch64.x[10],
			     (unsigned long long)record->registers.aarch64.x[11],
			     (unsigned long long)record->registers.aarch64.x[12],
			     (unsigned long long)record->registers.aarch64.x[13],
			     (unsigned long long)record->registers.aarch64.x[14],
			     (unsigned long long)record->registers.aarch64.x[15]);
			ebpf_info
			    ("Recovered crash registers: x16=0x%llx x17=0x%llx x18=0x%llx x19=0x%llx x20=0x%llx x21=0x%llx x22=0x%llx x23=0x%llx\n",
			     (unsigned long long)record->registers.aarch64.x[16],
			     (unsigned long long)record->registers.aarch64.x[17],
			     (unsigned long long)record->registers.aarch64.x[18],
			     (unsigned long long)record->registers.aarch64.x[19],
			     (unsigned long long)record->registers.aarch64.x[20],
			     (unsigned long long)record->registers.aarch64.x[21],
			     (unsigned long long)record->registers.aarch64.x[22],
			     (unsigned long long)record->registers.aarch64.x[23]);
			ebpf_info
			    ("Recovered crash registers: x24=0x%llx x25=0x%llx x26=0x%llx x27=0x%llx x28=0x%llx\n",
			     (unsigned long long)record->registers.aarch64.x[24],
			     (unsigned long long)record->registers.aarch64.x[25],
			     (unsigned long long)record->registers.aarch64.x[26],
			     (unsigned long long)record->registers.aarch64.x[27],
			     (unsigned long long)record->registers.aarch64.x[28]);
			return;
		}
		ebpf_info
		    ("Recovered crash registers (partial): pc=0x%llx sp=0x%llx x29=0x%llx x30=0x%llx x0=0x%llx x1=0x%llx x2=0x%llx x3=0x%llx x4=0x%llx x5=0x%llx x6=0x%llx x7=0x%llx\n",
		     (unsigned long long)record->ip,
		     (unsigned long long)record->sp,
		     (unsigned long long)record->fp,
		     (unsigned long long)record->lr,
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
		if (crash_record_has_full_regs(record))
			ebpf_info
			    ("Recovered crash registers: ip=0x%llx sp=0x%llx fp=0x%llx lr=0x%llx\n",
			     (unsigned long long)record->ip,
			     (unsigned long long)record->sp,
			     (unsigned long long)record->fp,
			     (unsigned long long)record->lr);
		else
			ebpf_info
			    ("Recovered crash registers (partial): ip=0x%llx sp=0x%llx fp=0x%llx lr=0x%llx\n",
			     (unsigned long long)record->ip,
			     (unsigned long long)record->sp,
			     (unsigned long long)record->fp,
			     (unsigned long long)record->lr);
		return;
	}
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

static void crash_log_frame_params(uint32_t index,
				  const struct crash_symbolized_frame *symbolized)
{
	if (symbolized == NULL || !symbolized->has_params ||
	    symbolized->params_text[0] == '\0')
		return;
	ebpf_info("Recovered crash frame[%u] params: %s\n", index,
		  symbolized->params_text);
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
		crash_log_frame_params(index, symbolized);
		return;
	}
	if (symbolized != NULL && symbolized->has_module) {
		ebpf_warning
		    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx\n",
		     index, (unsigned long long)frame->absolute_pc, module_path,
		     (unsigned long long)frame->rel_pc);
		crash_log_frame_params(index, symbolized);
		return;
	}
	ebpf_warning("Recovered crash frame[%u]: pc=0x%llx\n", index,
		     (unsigned long long)frame->absolute_pc);
	crash_log_frame_params(index, symbolized);
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
			crash_log_frame_params(index, symbolized);
			return;
		}
		ebpf_info
		    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx symbol=%s+0x%llx file=%s:%llu\n",
		     index, (unsigned long long)frame->absolute_pc, module_path,
		     (unsigned long long)frame->rel_pc, symbol_name,
		     (unsigned long long)symbol_offset, symbolized->file_path,
		     (unsigned long long)symbolized->line);
		crash_log_frame_params(index, symbolized);
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
			crash_log_frame_params(index, symbolized);
			return;
		}
		ebpf_info
		    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx file=%s:%llu\n",
		     index, (unsigned long long)frame->absolute_pc, module_path,
		     (unsigned long long)frame->rel_pc, symbolized->file_path,
		     (unsigned long long)symbolized->line);
		crash_log_frame_params(index, symbolized);
		return;
	}
	if (build_id[0] != '\0') {
		ebpf_info
		    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx symbol=%s+0x%llx build_id=%s\n",
		     index, (unsigned long long)frame->absolute_pc, module_path,
		     (unsigned long long)frame->rel_pc, symbol_name,
		     (unsigned long long)symbol_offset, build_id);
		crash_log_frame_params(index, symbolized);
		return;
	}
	ebpf_info
	    ("Recovered crash frame[%u]: pc=0x%llx module=%s rel=0x%llx symbol=%s+0x%llx\n",
	     index, (unsigned long long)frame->absolute_pc, module_path,
	     (unsigned long long)frame->rel_pc, symbol_name,
	     (unsigned long long)symbol_offset);
	crash_log_frame_params(index, symbolized);
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
	crash_log_registers(record);
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
