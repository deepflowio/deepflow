 /*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2025- The Yunshan Networks Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
 
 /*
  * Helper functions and definitions for Lua unwinding in eBPF programs
  * JIT related functions are kept separately for future extension,
  * like LJ2 and GC64 considerations.
  */

#pragma once

#define MAX_ENTRIES 10240
#define HOST_LEN 80

#define TAG_BITS     2
#define TAG_SHIFT    (64 - TAG_BITS)
#define TAG_MASK     (0x3ULL << TAG_SHIFT)
#define TAG_LUA      (0x0ULL << TAG_SHIFT)	/* 00 */
#define TAG_CFUNC    (0x1ULL << TAG_SHIFT)	/* 01 */
#define TAG_FFUNC    (0x2ULL << TAG_SHIFT)	/* 10 */

#if defined(__aarch64__)
#define LUAJIT_AARCH64_LAYOUT 1   /* LuaJIT unwinding supported on arm64 (GC64 mode on by default)*/
#else
#define LUAJIT_AARCH64_LAYOUT 0   /* Placeholder for x86_64 (GC32 mode)*/
#endif

#define FF_LUA 0
#define FF_C   1

#define LUA_STACK_MAP_ENTRIES    32768
#define LUA_INTP_STACK_ENTRIES   16384
#define LUA_TSTATE_ENTRIES       65536
#define LUA_OFFSET_PROFILES      8
#define LUA_EVENTS_MAX_CPUS      256
#define LUA_STATE_STACK_DEPTH    8

#define LANG_NONE    0u
#define LANG_LUA     (1u << 0)
#define LANG_LUAJIT  (1u << 1)

#define PACK_LUA_FRAME(meta32)   ((__u64)((meta32) & 0xffffffffull))
#define FRAME_META(x)            ((__u32)((x) & 0xffffffff))
#define FRAME_SYMID(x)           FRAME_META(x)

#define LUA_CLOSURE            (0u << 4)
#define LUA_LIGHT_C_FUNC       (1u << 4)
#define LUA_C_CLOSURE          (2u << 4)

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

struct lua_unwind_info_t {
	__u8 offsets_id;	/* entry in offsets map */
	__u8 reserved[7];	/* spare for alignment */
	__u64 state_address;	/* lua_State* in target */
};

struct lua_state_cache_t {
	__u64 states[LUA_STATE_STACK_DEPTH];
	__u8 depth;
	__u8 pad[7];
};

enum func_type {
	FUNC_TYPE_LUA,
	FUNC_TYPE_C,
	FUNC_TYPE_F,
	FUNC_TYPE_UNKNOWN,
};

#define LUA_FEAT_CI_ARRAY        (1u << 0)	/* 5.1 */
#define LUA_FEAT_CI_LINKED       (1u << 1)	/* 5.2+ */
#define LUA_FEAT_LINEINFO        (1u << 2)
#define LUA_FEAT_PC_INSTR_INDEX  (1u << 3)
#define LUA_FEAT_CLOSURE_ISC     (1u << 4)	/* 5.1 Closure.isC */
#define LUA_FEAT_LCF             (1u << 5)	/* 5.2+ light C functions */

#define LUA_TCOLLECTABLE 0x40

/* more fields than actually needed, for future use */
struct lj_ofs {
	__u8 fr2;		/* frame uses dual slots */
	__u8 gc64;		/* GC references are 64-bit */
	__u16 pad;		/* alignment padding */
	__u32 tv_sz;		/* sizeof(TValue) */
	__u32 off_l_base;	/* lua_State->base */
	__u32 off_l_stack;	/* lua_State->stack */
	__u32 off_gcproto_firstline;	/* GCproto->firstline */
	__u32 off_gcproto_chunkname;	/* GCproto->chunkname */
	__u32 off_gcstr_data;	/* GCstr->data */
	__u32 off_gcfunc_cfunc;	/* GCfunc->c.cfunc */
	__u32 off_gcfunc_ffid;	/* GCfunc->c.ffid */
	__u32 off_gcfunc_pc;	/* GCfunc->l.pc */
	__u32 off_gcproto_bc;	/* GCproto->bc */
	__u32 off_gcstr_len;	/* GCstr->len */
	__u32 off_l_glref;	/* lua_State->glref */
	__u32 off_global_state_dispatchmode;	/* global_State->dispatchmode */
};

struct lua_ofs {
	__u32 features;		/* feature flags (LUA_FEAT_*) */

	/* lua_State */
	__u32 off_l_ci;		/* lua_State->ci */
	__u32 off_l_base_ci;	/* lua_State->base_ci */
	__u32 off_l_end_ci;	/* lua_State->end_ci */

	/* CallInfo */
	__u32 off_ci_func;	/* CallInfo->func */
	__u32 off_ci_top;	/* CallInfo->top */
	__u32 off_ci_savedpc;	/* CallInfo->savedpc */
	__u32 off_ci_prev;	/* CallInfo->previous */

	/* TValue */
	__u32 off_tvalue_tt;	/* TValue->tt */
	__u32 off_tvalue_val;	/* TValue->value */

	/* Closure selector / union payloads */
	__u32 off_closure_isc;	/* Closure->c.isC */
	__u32 off_lclosure_p;	/* LClosure->p */
	__u32 off_cclosure_f;	/* CClosure->f */

	/* Proto */
	__u32 off_proto_source;	/* Proto->source */
	__u32 off_proto_linedefined;	/* Proto->linedefined */
	__u32 off_proto_code;	/* Proto->code */
	__u32 off_proto_sizecode;	/* Proto->sizecode */
	__u32 off_proto_lineinfo;	/* Proto->lineinfo */
	__u32 off_proto_abslineinfo;	/* Proto->abslineinfo */

	/* TString */
	__u32 off_tstring_len;	/* TString->len */
	__u32 sizeof_tstring;	/* sizeof(TString) */

	/* Sizes */
	__u32 sizeof_callinfo;	/* sizeof(CallInfo) */
	__u32 sizeof_tvalue;	/* sizeof(TValue) */
};

/* ----- helper functions ----- */

static __always_inline void *uadd(const void *p, __u32 off)
{
	return (void *)((unsigned long)p + off);
}

static __always_inline int uread(void *dst, const void *src, __u32 sz)
{
	return bpf_probe_read_user(dst, sz, src);
}

static __always_inline int uread_mref(void **p64, const void *src_mref)
{
#if LUAJIT_AARCH64_LAYOUT
	__u64 v = 0;
	int r = bpf_probe_read_user(&v, sizeof(v), src_mref);
	if (r) {
		return r;
	}
	*p64 = (void *)(unsigned long)v;
	return 0;
#else
	return -1;
#endif
}

static __always_inline void *decode_gcref_raw(__u64 raw, struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	__u64 ptr = raw & ((1ULL << 47) - 1);
	return (void *)(unsigned long)ptr;
#else
	return NULL;
#endif
}

static __always_inline int uread_gcref(void **dst, const void *pt,
				       struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	__u64 raw;
	int r = uread(&raw, uadd(pt, lj->off_gcproto_chunkname), sizeof(raw));
	if (r) {
		return r;
	}
	*dst = decode_gcref_raw(raw, lj);
	return 0;
#else
	return -1;
#endif
}

static __always_inline int gcfunc_get_proto(void *fn, void **ppt,
											const struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	// 1) read MRef l.pc (treat as 64 bits; works for both GC64 and non-GC64)
	__u64 pc_raw = 0;
	void *pc_addr = (void *)((unsigned long)fn + lj->off_gcfunc_pc);
	int r = bpf_probe_read_user(&pc_raw, sizeof(pc_raw), pc_addr);
	if (r) {
		return r;
	}

	// 2) GC64 "inflate if needed":
	// If upper bits look empty, borrow them from 'fn' (same GC arena).
	// LOW_MASK ~ 47-bit user VA (works on x86_64/aarch64 canonical addresses).
	const __u64 LOW_MASK = (1ULL << 47) - 1;
	const __u64 HI_MASK  = ~LOW_MASK;

	if ((pc_raw & HI_MASK) == 0) {
		__u64 hi = ((__u64)(unsigned long)fn) & HI_MASK;
		if (!hi) {
			// weak fallback: borrow from the address of the field we read
			hi = ((__u64)(unsigned long)pc_addr) & HI_MASK;
			if (!hi) {
				// last-ditch: borrow from fn adjusted by bc offset
				hi = (((__u64)(unsigned long)fn) - (unsigned long)lj->off_gcproto_bc) & HI_MASK;
			}
		}
		pc_raw |= hi;
	}

	// 3) back up by proto->bc offset
	void *pt = (void *)((unsigned long)pc_raw - (unsigned long)lj->off_gcproto_bc);

	*ppt = pt;
	return 0;
#else
	return -1;
#endif
}

static __always_inline int L_get_base(void *L, void **base, struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	return uread((void **)base, uadd(L, lj->off_l_base), sizeof(void *));
#else
	return -1;
#endif
}

static __always_inline int L_get_stack(void *L, void **stack, struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	return uread_mref((void **)stack, uadd(L, lj->off_l_stack));
#else
	return -1;
#endif
}

static __always_inline int proto_get_firstline(void *pt, int *pline,
					       struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	return uread(pline, uadd(pt, lj->off_gcproto_firstline),
		     sizeof(*pline));
#else
	return -1;
#endif
}

static __always_inline int gcfunc_get_cfunc(void *fn, void **cfuncp,
					    struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	return uread(cfuncp, uadd(fn, lj->off_gcfunc_cfunc), sizeof(*cfuncp));
#else
	return -1;
#endif
}

static __always_inline int gcfunc_get_ffid(void *fn, __u8 * pffid,
					   struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	return uread(pffid, uadd(fn, lj->off_gcfunc_ffid), sizeof(*pffid));
#else
	return -1;
#endif
}

static __always_inline int is_luafunc(void *fn, struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	__u8 ffid;
	if (gcfunc_get_ffid(fn, &ffid, lj)) {
		return -1;
	}
	return ffid == FF_LUA;
#else
	return -1;
#endif
}

static __always_inline int is_cfunc(void *fn, struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	__u8 ffid;
	if (gcfunc_get_ffid(fn, &ffid, lj)) {
		return -1;
	}
	return ffid == FF_C;
#else
	return -1;
#endif
}

static __always_inline int is_ffunc(void *fn, struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	__u8 ffid;
	if (gcfunc_get_ffid(fn, &ffid, lj)) {
		return -1;
	}
	return ffid > FF_C;
#else
	return -1;
#endif
}

static __always_inline int get_frame_ftsz(void *frame, __u64 * ftsz,
					  struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	return uread(ftsz, frame, sizeof(__u64));
#else
	return -1;
#endif
}

static __always_inline int get_frame_gc_ptr(void *frame, void **gc_ptr,
					    struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	void *gcref_slot = (void *)((char *)frame - lj->tv_sz);
	__u64 gcref_raw;
	if (uread(&gcref_raw, gcref_slot, sizeof(gcref_raw))) {
		return -1;
	}

	if (lj->gc64) {
		*gc_ptr = (void *)(gcref_raw & 0x7FFFFFFFFFFFULL);
	} else {
		*gc_ptr = (void *)(unsigned long)(__u32) gcref_raw;
	}
	return 0;
#else
	return -1;
#endif
}

static __always_inline int frame_islua_wr(void *frame, struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	__u64 ftsz;
	if (get_frame_ftsz(frame, &ftsz, lj)) {
		return -1;
	}

	return (ftsz & 3) == 0;
#else
	return -1;
#endif
}

static __always_inline int frame_isvarg_wr(void *frame, struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	__u64 ftsz;
	if (get_frame_ftsz(frame, &ftsz, lj)) {
		return -1;
	}

	return (ftsz & 7) == 3;
#else
	return -1;
#endif
}

static __always_inline void *frame_func_wr(void *frame, struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	void *frame_gc_ptr;
	if (get_frame_gc_ptr(frame, &frame_gc_ptr, lj)) {
		return NULL;
	}

	return frame_gc_ptr;
#else
	return NULL;
#endif
}

static __always_inline int frame_gc_equals_L(void *frame, void *L,
					     struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	void *frame_gc_ptr;
	if (get_frame_gc_ptr(frame, &frame_gc_ptr, lj)) {
		return -1;
	}

	return frame_gc_ptr == L;
#else
	return -1;
#endif
}
static __always_inline int frame_pc_prev_wr(const void *pc, __u32 *prev_bc)
{
#if LUAJIT_AARCH64_LAYOUT
	return uread(prev_bc, (const char *)pc - sizeof(*prev_bc),
		     sizeof(*prev_bc));
#else
	return -1;
#endif
}

static __always_inline void *frame_prevl_wr(void *frame, struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	__u64 savedpc_raw = 0;
	if (get_frame_ftsz(frame, &savedpc_raw, lj)) {
		return NULL;
	}

	const void *pc = (const void *)(uintptr_t)savedpc_raw;
	if (!pc) {
		return NULL;
	}

	__u32 bc_prev = 0;
	if (frame_pc_prev_wr(pc, &bc_prev)) {
		return NULL;
	}

	__u32 bc_a_val = (bc_prev >> 8) & 0xff;
	__u32 slots = 1 + (lj ? lj->fr2 : 0) + bc_a_val;
	const __u32 slot_bytes = 8;

	return (char *)frame - (size_t)slots * slot_bytes;
#else
	return NULL;
#endif
}

static __always_inline void *frame_prevd_wr(void *frame, struct lj_ofs *lj)
{
#if LUAJIT_AARCH64_LAYOUT
	__u64 ftsz = 0;
	if (get_frame_ftsz(frame, &ftsz, lj)) {
		return NULL;
	}

	__u64 frame_sized = ftsz & ~0x7ULL;
	if (!frame_sized) {
		return NULL;
	}

	return (char *)frame - (size_t)frame_sized;
#else
	return NULL;
#endif
}
