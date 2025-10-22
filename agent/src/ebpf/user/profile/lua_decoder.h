/*
 * Copyright (c) 2025 Yunshan Networks
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

#ifndef DF_USER_PROFILE_LUA_DECODER_H
#define DF_USER_PROFILE_LUA_DECODER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stdint.h>
#include <linux/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "../log.h"

#ifndef HAVE_PROCESS_VM_READV_DECL
ssize_t process_vm_readv(pid_t pid,
			 const struct iovec *local_iov, unsigned long liovcnt,
			 const struct iovec *remote_iov, unsigned long riovcnt,
			 unsigned long flags);
#endif

#define LUA_CHUNK_READ_MAX 4096U	/* Clamp chunk reads to avoid oversized allocations. */

#define TAG_BITS     2
#define TAG_SHIFT    (64 - TAG_BITS)
#define TAG_MASK     (0x3ULL << TAG_SHIFT)
#define TAG_LUA      (0x0ULL << TAG_SHIFT)	/* Lua proto pointer. */
#define TAG_CFUNC    (0x1ULL << TAG_SHIFT)	/* Native C function. */
#define TAG_FFUNC    (0x2ULL << TAG_SHIFT)	/* LuaJIT fast function id. */

#define LANG_LUA     (1u << 0)
#define LANG_LUAJIT  (1u << 1)

/* Metadata placed in lua_unwind_info_map by user space. */
struct lua_unwind_info_t {
	__u8 offsets_id;	/* entry in offsets map */
	__u8 reserved[7];	/* spare for alignment */
	__u64 state_address;	/* lua_State* in target */
};

/* Layout hints for LuaJIT GC objects used during symbolization. */
struct lj_ofs {
	__u8 fr2;		/* frames use two stack slots */
	__u8 gc64;		/* 64-bit GC reference flag */
	__u16 pad;		/* alignment padding */
	__u32 off_l_base;	/* lua_State->base */
	__u32 off_l_stack;	/* lua_State->stack */
	__u32 off_gcproto_firstline;	/* GCproto->firstline */
	__u32 off_gcproto_chunkname;	/* GCproto->chunkname */
	__u32 off_gcstr_data;	/* GCstr->data */
	__u32 off_gcfunc_cfunc;	/* GCfunc->c.pc->cfunc */
	__u32 off_gcfunc_ffid;	/* GCfunc->c.ffid */
	__u32 off_gcfunc_pc;	/* GCfunc->l.pc */
	__u32 off_gcproto_bc;	/* GCproto->bc */
	__u32 off_gcstr_len;	/* GCstr->len */
	__u32 off_l_glref;	/* lua_State->glref */
	__u32 off_global_state_dispatchmode;	/* global_State->dispatchmode */
};

/* Layout hints for vanilla Lua 5.x structures (lua_State, Proto, etc.). */
struct lua_ofs {
	__u32 features;		/* feature flags (LUA_FEAT_*) */
	__u32 off_l_ci;		/* lua_State->ci */
	__u32 off_l_base_ci;	/* lua_State->base_ci */
	__u32 off_l_end_ci;	/* lua_State->end_ci */
	__u32 off_ci_func;	/* CallInfo->func */
	__u32 off_ci_top;	/* CallInfo->top */
	__u32 off_ci_savedpc;	/* CallInfo->savedpc */
	__u32 off_ci_prev;	/* CallInfo->previous */
	__u32 off_tvalue_tt;	/* TValue->tt */
	__u32 off_tvalue_val;	/* TValue->value */
	__u32 off_closure_isc;	/* Closure->c.isC */
	__u32 off_lclosure_p;	/* LClosure->p */
	__u32 off_cclosure_f;	/* CClosure->f */
	__u32 off_proto_source;	/* Proto->source */
	__u32 off_proto_linedefined;	/* Proto->linedefined */
	__u32 off_proto_code;	/* Proto->code */
	__u32 off_proto_sizecode;	/* Proto->sizecode */
	__u32 off_proto_lineinfo;	/* Proto->lineinfo */
	__u32 off_proto_abslineinfo;	/* Proto->abslineinfo */
	__u32 off_tstring_len;	/* TString->len */
	__u32 sizeof_tstring;	/* sizeof(TString) */
	__u32 sizeof_callinfo;	/* sizeof(CallInfo) */
	__u32 sizeof_tvalue;	/* sizeof(TValue) */
};

static inline int lua_read_target_mem(pid_t pid, uintptr_t addr, void *buf,
				      size_t len)
{
	if (!addr || !buf || !len)
		return -EINVAL;

	struct iovec local = {
		.iov_base = buf,
		.iov_len = len,
	};
	struct iovec remote = {
		.iov_base = (void *)addr,
		.iov_len = len,
	};

	ssize_t got = process_vm_readv(pid, &local, 1, &remote, 1, 0);
	if (got < 0) {
		int err = errno;
		ebpf_warning
		    ("lua_read_target_mem: process_vm_readv(pid=%d, remote=0x%llx, len=%zu) failed: %s (%d)",
		     pid, (unsigned long long)addr, len, strerror(err), err);
		return -err;
	}
	if ((size_t) got != len) {
		ebpf_warning
		    ("lua_read_target_mem: short read pid=%d remote=0x%llx expected=%zu got=%zd",
		     pid, (unsigned long long)addr, len, got);
		return -EIO;
	}
	return 0;
}

static inline bool lua_decode_lua_chunkname(const struct lua_ofs *lua_ofs,
					    pid_t pid, uintptr_t proto_addr,
					    char *dst, size_t dst_sz)
{
	if (!lua_ofs || !dst || dst_sz < 2)
		return false;

	uintptr_t ts_ptr = 0;
	if (lua_read_target_mem(pid,
				proto_addr + lua_ofs->off_proto_source,
				&ts_ptr, sizeof(ts_ptr)) != 0 || ts_ptr == 0)
		return false;

	size_t max_copy = dst_sz - 1;
	if (max_copy == 0)
		return false;

	uint32_t len = 0;
	bool have_len = lua_ofs->off_tstring_len != 0;
	if (have_len) {
		if (lua_read_target_mem(pid,
					ts_ptr + lua_ofs->off_tstring_len,
					&len, sizeof(len)) != 0)
			return false;
		if (len > LUA_CHUNK_READ_MAX)
			len = LUA_CHUNK_READ_MAX;
	} else {
		len = max_copy;
	}

	if (len > max_copy)
		len = max_copy;

	if (len &&
	    lua_read_target_mem(pid,
				ts_ptr + lua_ofs->sizeof_tstring,
				dst, len) != 0)
		return false;

	dst[len] = '\0';
	return len > 0 || have_len;
}

static inline bool lua_decode_luajit_chunkname(const struct lj_ofs *lj_ofs,
					       pid_t pid, uintptr_t proto_addr,
					       char *dst, size_t dst_sz)
{
	if (!lj_ofs || !dst || dst_sz < 2)
		return false;

	uint64_t raw_ref = 0;
	if (lua_read_target_mem(pid,
				proto_addr + lj_ofs->off_gcproto_chunkname,
				&raw_ref, sizeof(raw_ref)) != 0)
		return false;

	uintptr_t gcs_ptr = 0;
	if (lj_ofs->gc64)
		gcs_ptr = (uintptr_t) (raw_ref & ((1ULL << 47) - 1));
	else
		gcs_ptr = (uintptr_t) (uint32_t) raw_ref;

	if (gcs_ptr == 0)
		return false;

	uint32_t len = 0;
	if (lua_read_target_mem(pid,
				gcs_ptr + lj_ofs->off_gcstr_len,
				&len, sizeof(len)) != 0)
		return false;

	size_t max_copy = dst_sz - 1;
	size_t copy_len = len;
	if (copy_len > LUA_CHUNK_READ_MAX)
		copy_len = LUA_CHUNK_READ_MAX;
	if (copy_len > max_copy)
		copy_len = max_copy;

	if (copy_len &&
	    lua_read_target_mem(pid,
				gcs_ptr + lj_ofs->off_gcstr_data,
				dst, copy_len) != 0)
		return false;

	dst[copy_len] = '\0';
	return copy_len > 0 || len == 0;
}

static inline bool lua_decode_chunkname(pid_t pid, uintptr_t proto_addr,
					__u32 lang_flags,
					const struct lua_ofs *lua_ofs,
					const struct lj_ofs *lj_ofs,
					char *dst, size_t dst_sz)
{
	if (!proto_addr)
		return false;

	if ((lang_flags & LANG_LUAJIT) &&
	    lua_decode_luajit_chunkname(lj_ofs, pid, proto_addr, dst, dst_sz))
		return true;

	if ((lang_flags & LANG_LUA) &&
	    lua_decode_lua_chunkname(lua_ofs, pid, proto_addr, dst, dst_sz))
		return true;

	return false;
}

static inline __u32 lua_decode_firstline(pid_t pid, uintptr_t proto_addr,
					 __u32 lang_flags,
					 const struct lua_ofs *lua_ofs,
					 const struct lj_ofs *lj_ofs)
{
	if ((lang_flags & LANG_LUA) && lua_ofs) {
		int line = 0;
		if (lua_read_target_mem(pid,
					proto_addr +
					lua_ofs->off_proto_linedefined, &line,
					sizeof(line)) == 0 && line > 0)
			return (__u32) line;
	}

	if ((lang_flags & LANG_LUAJIT) && lj_ofs) {
		int line = 0;
		if (lua_read_target_mem(pid,
					proto_addr +
					lj_ofs->off_gcproto_firstline, &line,
					sizeof(line)) == 0 && line > 0)
			return (__u32) line;
	}

	return 0;
}

#endif /* DF_USER_PROFILE_LUA_DECODER_H */
