/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2022- The Yunshan Networks Authors.
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

 
#include <linux/bpf_perf_event.h>
#include "config.h"
#include "bpf_base.h"
#include "common.h"
#include "kernel.h"
#include "bpf_endian.h"
#include "lua_profile.h"


#define FF_LUA 0
#define FF_C 1

// Frame type constants
#define FRAME_TYPE 3
#define FRAME_LUA 0
#define FRAME_VARG 3
#define FRAME_TYPEP 7

#define MAX_ENTRIES 10240

#define SYM_SCAN_RECENT 64



#define LUA_STACK_MAP_ENTRIES    32768
#define LUA_INTP_STACK_ENTRIES   16384
#define LUA_TSTATE_ENTRIES       65536
#define LUA_OFFSET_PROFILES      8
#define LUA_EVENTS_MAX_CPUS      256


const volatile bool include_idle = false;
const volatile pid_t targ_pid = -1;
const volatile pid_t targ_tid = -1;
const volatile __u64 targ_ns_dev = 0;
const volatile __u64 targ_ns_ino = 0;
const volatile __u64 stack_depth_limit = 16;
const volatile bool is_lua = false;



#include "lua_unwind_helper.h"
/* ------------------ maps for stack emit ------------------ */

MAP_STACK_TRACE(stack_map, LUA_STACK_MAP_ENTRIES, FEATURE_FLAG_PROFILE_ONCPU)

MAP_HASH(intp_stack_map, __u32, struct lua_stack_t, LUA_INTP_STACK_ENTRIES, FEATURE_FLAG_PROFILE_ONCPU)

MAP_HASH(lua_tstate_map, __u32, __u64, LUA_TSTATE_ENTRIES, FEATURE_FLAG_PROFILE_ONCPU)

MAP_PERARRAY(intp_stack_scratch, __u32, struct lua_stack_t, 1, FEATURE_FLAG_PROFILE_ONCPU)

MAP_PERF_EVENT(events, int, __u32, LUA_EVENTS_MAX_CPUS, FEATURE_FLAG_PROFILE_ONCPU)

MAP_PERARRAY(heap, __u32, struct stack_trace_key_t, 1, FEATURE_FLAG_PROFILE_ONCPU)

MAP_HASH(lang_flags_map, __u32, __u32, LUA_TSTATE_ENTRIES, FEATURE_FLAG_PROFILE_ONCPU)

MAP_HASH(lua_unwind_info_map, __u32, struct lua_unwind_info_t, LUA_TSTATE_ENTRIES, FEATURE_FLAG_PROFILE_ONCPU)

MAP_HASH(lua_offsets_map, __u32, struct lua_ofs, LUA_OFFSET_PROFILES, FEATURE_FLAG_PROFILE_ONCPU)

MAP_HASH(luajit_offsets_map, __u32, struct lj_ofs, LUA_OFFSET_PROFILES, FEATURE_FLAG_PROFILE_ONCPU)

#define SYMBOL_TABLE_MAX_ENTRIES 1024
#define SYMBOL_SCAN_MAX 16


static __always_inline void add_frame(struct lua_stack_t *st, __u64 addr, __u64 tag)
{
    if (st->len < INTP_MAX_STACK_DEPTH) {
        st->frames[st->len].addr = addr;
        st->frames[st->len].tag = tag;
        st->len++;
    }
}

static __always_inline __u64 encode_lua_frame(__u32 meta)
{
    return TAG_LUA | ((__u64)meta & 0xFFFFFFFFull);
}

MAP_PERARRAY(symbol_counter, __u32, __u32, 1, FEATURE_FLAG_PROFILE_ONCPU)

static __always_inline int lua_unwind(struct bpf_perf_event_data *ctx, __u32 tid, void *L, __u32 off_id, struct lua_stack_t *intp_stack)
{
    struct lua_ofs *o;
    o = lua_offsets_map__lookup(&off_id);
    if (!o || !intp_stack) {
        return 0;
    }

    void *ci = NULL, *base_ci = NULL, *end_ci = NULL;
    if (bpf_probe_read_user(&ci, sizeof(ci), (char *)L + o->off_L_ci)) {
        return 0;
    }
    
    // base_ci end_ci for Lua 5.1
    if (o->features & LUA_FEAT_CI_ARRAY) {
        if (bpf_probe_read_user(&base_ci, sizeof(base_ci), (char *)L + o->off_L_base_ci)) {
            return 0;
        }
        if (bpf_probe_read_user(&end_ci,  sizeof(end_ci),  (char *)L + o->off_L_end_ci))  {
            return 0;
        }
        if (!ci || !base_ci || !end_ci) {
            return 0;
        }
    }

    #pragma clang loop unroll(disable)
    for (int i = 0; i < stack_depth_limit; i++) {
        if (intp_stack->len >= INTP_MAX_STACK_DEPTH)
            break;

        if (o->features & LUA_FEAT_CI_ARRAY) {
            if ((char *)ci < (char *)base_ci || (char *)ci >= (char *)end_ci)
                break;
        }


        // Load fields from this CallInfo
        void *ci_func = NULL, *savedpc = NULL, *ci_prev = NULL;
        if (bpf_probe_read_user(&ci_func, sizeof(ci_func), (char *)ci + o->off_CI_func)) {
            goto next_frame;
        }
        (void)bpf_probe_read_user(&savedpc, sizeof(savedpc), (char *)ci + o->off_CI_savedpc);
        (void)savedpc;
        // ci_prev available in Lua 5.2+
        if (o->features & LUA_FEAT_CI_LINKED)
            (void)bpf_probe_read_user(&ci_prev, sizeof(ci_prev), (char*)ci + o->off_CI_prev);

        int tt = -1;
        if (bpf_probe_read_user(&tt, sizeof(tt), (char *)ci_func + o->off_TValue_tt)) {
            goto next_frame;
        }

        int variant = tt & 0x30;
        bool is_collectable = (tt & LUA_TCOLLECTABLE) != 0;

        void *valp = NULL;
        (void)bpf_probe_read_user(&valp, sizeof(valp),
                                  (char*)ci_func + (o->off_TValue_val ? o->off_TValue_val : 0));

        void *cl = valp;

        if (o->features & LUA_FEAT_LCF) {
            if (variant == (0<<4) && is_collectable) {
                void *proto = NULL;
                if (!cl || bpf_probe_read_user(&proto, sizeof(proto), (char*)cl + o->off_LClosure_p) || !proto) {
                    goto next_frame;
                }
                __u64 enc = encode_lua_frame(0);
                add_frame(intp_stack, (__u64)proto, enc);
            } else if (variant == (2<<4) && is_collectable) {
                void *f = NULL;
                if (cl && !bpf_probe_read_user(&f, sizeof(f), (char*)cl + o->off_CClosure_f) && f) {
                    __u64 enc = TAG_CFUNC | (((__u64)f) & ~TAG_MASK);
                    add_frame(intp_stack, (__u64)f, enc);
                }
            } else if (variant == (1<<4) && !is_collectable) {
                if (valp) {
                    __u64 enc = TAG_CFUNC | (((__u64)valp) & ~TAG_MASK);
                    add_frame(intp_stack, (__u64)valp, enc);
                }
            } else {
                goto next_frame;
            }

        } else {

            __u8 isC = 0;
            if (bpf_probe_read_user(&isC, sizeof(isC), (char*)cl + o->off_Closure_isC)) {
                goto next_frame;
            }

            if (!isC) {
                void *proto = NULL;
                if (bpf_probe_read_user(&proto, sizeof(proto), (char*)cl + o->off_LClosure_p)) {
                    goto next_frame;
                }
                __u64 enc = encode_lua_frame(0);
                add_frame(intp_stack, (__u64)proto, enc);
            } else {
                void *cf = NULL;
                if (bpf_probe_read_user(&cf, sizeof(cf), (char*)cl + o->off_CClosure_f)) {
                    goto next_frame;
                }
                __u64 enc = TAG_CFUNC | (((__u64)cf) & ~TAG_MASK);
                add_frame(intp_stack, (__u64)cf, enc);
            }
        }

    next_frame:
        if (o->features & LUA_FEAT_CI_LINKED) {
            if (!ci_prev) break;
            ci = ci_prev;
            continue;
        } else {
            ci = (void *)((char *)ci - o->sizeof_CallInfo);
        }
    }

    return 0;
}



static inline int lua_get_funcdata(struct bpf_perf_event_data *ctx, void *frame, struct lua_stack_t *intp_stack, struct lj_ofs *o)
{
	if (!frame)
	{
		return -1;
	}

	void *fn = frame_func_wr(frame, o);
	if (!fn)
	{
		return -1;
	}

	if (is_luafunc(fn, o))
	{
		void *pt = NULL;
		if (gcfunc_get_proto(fn, &pt, o)) {
			return -1;
		}
        
        __u64 enc = encode_lua_frame(0);
        add_frame(intp_stack, (__u64)pt, enc);
	}
	else if (is_cfunc(fn, o))
		{
			void *cf = NULL;
			if (gcfunc_get_cfunc(fn, &cf, o)) return -1;
            __u64 enc = TAG_CFUNC | (((__u64)cf) & ~TAG_MASK);
            add_frame(intp_stack, (__u64)cf, enc);
		}
	else if (is_ffunc(fn, o))
			{
				__u8 ffid = 0;
				if (gcfunc_get_ffid(fn, &ffid, o)) return -1;
                __u64 enc = TAG_FFUNC | (__u64)ffid;
                add_frame(intp_stack, 0, enc);
	}
	else {
        add_frame(intp_stack, 0, TAG_MASK);
        return -1;
    }
	return 0;
}

static int luajit_unwind(struct bpf_perf_event_data *ctx, __u32 tid, void *L, __u32 off_id, struct lua_stack_t *intp_stack)
{

    struct lj_ofs *o;
    o = luajit_offsets_map__lookup(&off_id);
    if (!o) return 0;
    
    if (o->fr2)
        return 0;

    if (!intp_stack) return -1;

    int level = 1;

    void *stack_ptr, *base_ptr;
    if(L_get_stack(L, &stack_ptr, o)) return -1;
    if(L_get_base(L, &base_ptr, o)) return -1;
    
    // TODO: remove hardcoded TValue size, add lj.tv_size
	void *bot = (void *)((char *)stack_ptr + (o->fr2 ? 16 : 0));

	void *frame, *nextframe;
	frame = nextframe = (void *)((char *)base_ptr - 8);


	// Main frame walker loop
    int i = 0;
    for (; i < stack_depth_limit && frame > bot; i++) {
        if (frame_gc_equals_L(frame, L, o) > 0) {
            level++;
        }
        if (level-- == 0) {
            level++;
            if (intp_stack->len >= INTP_MAX_STACK_DEPTH) {
                break;
            }
            if (lua_get_funcdata(ctx, frame, intp_stack, o) != 0) {
                continue;
            }
        }
        nextframe = frame;

        if (frame_islua_wr(frame, o)) {
            frame = frame_prevl_wr(frame, o);
        } else {
            if (frame_isvarg_wr(frame, o))
                level++;
            frame = frame_prevd_wr(frame, o);
        }
    }
    return 0;
}


static long get_current_pid_tgid(__u32 *pid, __u32 *tid)
{
    __u64 id = bpf_get_current_pid_tgid();
    *pid = id >> 32;
    *tid = id;
    return 0;
}


static __always_inline int perf_event_common(struct bpf_perf_event_data *ctx,
                                             struct stack_trace_key_t **keypp,
                                             struct lua_stack_t **intp_stackpp,
                                             __u32 *tgidp,
                                             __u32 *tidp,
                                             void **Lp)
{
    __u32 tgid = 0, tid = 0;
    if (get_current_pid_tgid(&tgid, &tid))
        return -1;

    __u32 zero = 0;
    struct stack_trace_key_t *key = heap__lookup(&zero);
    if (!key) return -1;

    struct lua_stack_t *intp_stack = intp_stack_scratch__lookup(&zero);
    if (!intp_stack) return -1;
    intp_stack->len = 0;

    if (!include_idle && tid == 0)
        return -1;

    if (targ_pid != -1 && targ_pid != tgid)
        return -1;
    if (targ_tid != -1 && targ_tid != tid)
        return -1;

    key->tgid = tgid;
    key->tid = tid;
    bpf_get_current_comm(&key->comm, sizeof(key->comm));
    key->kernstack = bpf_get_stackid(&ctx->regs, &NAME(stack_map), 0);
    key->userstack = bpf_get_stackid(&ctx->regs, &NAME(stack_map), BPF_F_USER_STACK);
    key->intpstack = -1;
    key->flags = 0;

    if (key->userstack == 0)
        return -1;

    __u64 *Lptr = lua_tstate_map__lookup(&tid);
    if (!Lptr || *Lptr == 0)
        return -1;

    *keypp = key;
    *intp_stackpp = intp_stack;
    if (tgidp) *tgidp = tgid;
    if (tidp) *tidp = tid;
    if (Lp) *Lp = (void *)(*Lptr);
    return 0;
}

static __always_inline void finalize_sample(struct bpf_perf_event_data *ctx,
                                            struct stack_trace_key_t *key,
                                            struct lua_stack_t *intp_stack)
{
    if (intp_stack && intp_stack->len > 0) {
        __u32 intp_key = key->userstack;
        if (intp_stack_map__update(&intp_key, intp_stack) == 0) {
            key->intpstack = (__s32)intp_key;
        }
    }

    bpf_perf_event_output(ctx, &NAME(events), BPF_F_CURRENT_CPU, key, sizeof(*key));
}

SEC("perf_event")
int do_perf_event_lua(struct bpf_perf_event_data *ctx)
{
    struct stack_trace_key_t *key = NULL;
    struct lua_stack_t *intp_stack = NULL;
    __u32 tgid = 0, tid = 0;
    void *L = NULL;

    if (perf_event_common(ctx, &key, &intp_stack, &tgid, &tid, &L))
        return 0;

    __u32 *flags = lang_flags_map__lookup(&tgid);
    if (!flags)
        return 0;
    key->flags = (__u16)(*flags);
    if (!(*flags & LANG_LUA))
        return 0;

    struct lua_unwind_info_t *uw = lua_unwind_info_map__lookup(&tgid);
    if (!uw)
        return 0;

    __u32 off_id = uw->offsets_id;
    (void)lua_unwind(ctx, tid, L, off_id, intp_stack);

    finalize_sample(ctx, key, intp_stack);
    return 0;
}

SEC("perf_event")
int do_perf_event_luajit(struct bpf_perf_event_data *ctx)
{
    struct stack_trace_key_t *key = NULL;
    struct lua_stack_t *intp_stack = NULL;
    __u32 tgid = 0, tid = 0;
    void *L = NULL;

    if (perf_event_common(ctx, &key, &intp_stack, &tgid, &tid, &L))
        return 0;

    __u32 *flags = lang_flags_map__lookup(&tgid);
    if (!flags)
        return 0;
    key->flags = (__u16)(*flags);
    if (!(*flags & LANG_LUAJIT))
        return 0;

    struct lua_unwind_info_t *uw = lua_unwind_info_map__lookup(&tgid);
    if (!uw)
        return 0;

    __u32 off_id = uw->offsets_id;
    (void)luajit_unwind(ctx, tid, L, off_id, intp_stack);

    finalize_sample(ctx, key, intp_stack);
    return 0;
}

static int probe_entry_lua_cancel(struct pt_regs *ctx)
{
    if (!PT_REGS_PARM2(ctx))
        return 0;
    if (!PT_REGS_PARM4(ctx))
        return 0;

    __u32 pid = 0, tid = 0;
    if (get_current_pid_tgid(&pid, &tid))
        return 0;

    if (targ_pid != -1 && targ_pid != pid)
        return 0;
    lua_tstate_map__delete(&tid);
    return 0;
}

UPROG(handle_entry_lua_cancel)
 (struct pt_regs *ctx)
{
	return probe_entry_lua_cancel(ctx);
}

static int probe_entry_lua(struct pt_regs *ctx)
{
    void *param1 = (void *)PT_REGS_PARM1(ctx);
    if (!param1)
        return 0;

    __u32 pid = 0, tid = 0;
    if (get_current_pid_tgid(&pid, &tid))
        return 0;

    if (targ_pid != -1 && targ_pid != pid)
        return 0;

    __u64 L = (__u64)param1;
    lua_tstate_map__update(&tid, &L);
    return 0;
}

UPROG(handle_entry_lua)
 (struct pt_regs *ctx)
{
	return probe_entry_lua(ctx);
}

char LICENSE[] SEC("license") = "GPL";
