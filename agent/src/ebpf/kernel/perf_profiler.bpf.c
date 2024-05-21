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
#include "perf_profiler.h"
#include "rust_bindings.h"

#define KERN_STACKID_FLAGS (0)
#define USER_STACKID_FLAGS (0 | BPF_F_USER_STACK)

/*
 * To keep the stack trace profiler "always on," we utilize a double
 * buffering mechanism and allocate two identical data structures. 
 *
 * 1 stack_map Used to collect the call stack information of kernel
 *   functions. Used to collect the call stack information. Maps the
 *   entire stack trace with stack IDs.
 * 
 * 2 profiler_output perf output to user space, Through hash-table,
 *   user space can be used to collect call stack information. The
 *   higher the count, the more we observe certain stack traces, some
 *   of which may indicate potential performance issues.
 *
 * We implement continuous tracking using a double buffering scheme,
 * for which we allocate two data structures. Therefore, we have the
 * following BPF tables:
 *
 *   1 profiler_output_a
 *   2 profiler_output_b
 *   3 stack_map_a
 *   4 stack_map_b
 *
 * User space controls the switching between MAP a and MAP b. It ensures
 * that when reading data from cache a for address symbolization, BPF uses
 * cache b for writing data and vice versa.
 */

MAP_PERF_EVENT(profiler_output_a, int, __u32, MAX_CPU)
MAP_PERF_EVENT(profiler_output_b, int, __u32, MAX_CPU)

MAP_STACK_TRACE(stack_map_a, STACK_MAP_ENTRIES)
MAP_STACK_TRACE(stack_map_b, STACK_MAP_ENTRIES)

MAP_PROG_ARRAY(progs_jmp_perf_map, __u32, __u32, PROG_PERF_NUM)
MAP_PROG_ARRAY(progs_jmp_uprobe_map, __u32, __u32, PROG_PERF_NUM)
struct bpf_map_def SEC("maps") __python_symbols = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	__BPF_MAP_DEF(symbol_t, __u32, 512),
};
MAP_PERARRAY(heap, __u32, unwind_state_t, 1)
MAP_PERARRAY(python_symbol_index, __u32, __u32, 1)
MAP_HASH(python_stack, __u64, stack_trace_t, STACK_MAP_ENTRIES)
MAP_HASH(python_tstate_addr, __u32, __u64, 65536)
MAP_HASH(dwarf_shard_table, __u32, shard_info_list_t, 128)
MAP_HASH(dwarf_unwind_table, __u32, unwind_entry_shard_t, 40)

static inline __attribute__((always_inline)) bool comm_eq_n(char *a, char *b, int n) {
#pragma unroll
	for (int i = 0; i < TASK_COMM_LEN && i < n; i++) {
		if (a[i] == '\0' || b[i] == '\0') {
			return a[i] == b[i];
		}
		if (a[i] != b[i]) {
			return false;
		}
	}
	return true;
}

struct {
	struct {
		__s64 current_frame;
	} py_cframe;
	struct {
		__s64 co_filename;
		__s64 co_name;
		__s64 co_varnames;
		__s64 co_firstlineno;
	} py_code_object;
	struct {
		__s64 f_back;
		__s64 f_code;
		__s64 f_lineno;
		__s64 f_localsplus;
	} py_frame_object;
	struct {
		__s64 ob_type;
	} py_object;
	struct {
		__s64 data;
		__s64 size;
	} py_string;
	struct {
		__s64 next;
		__s64 interp;
		__s64 frame;
		__s64 thread_id;
		__s64 native_thread_id;
		__s64 cframe;
	} py_thread_state;
	struct {
		__s64 ob_item;
	} py_tuple_object;
	struct {
		__s64 tp_name;
	} py_type_object;
	struct {
		__s64 owner;
	} py_interpreter_frame;
} py_offsets = {
	.py_cframe = {
		.current_frame = 0,
	},
	.py_code_object = {
		.co_filename = 104,
		.co_name = 112,
		.co_varnames = 72,
		.co_firstlineno = 40,
	},
	.py_frame_object = {
		.f_back = 24,
		.f_code = 32,
		.f_lineno = 100,
		.f_localsplus = 352,
	},
	.py_object = {
		.ob_type = 8,
	},
	.py_string = {
		.data = 48,
		.size = -1,
	},
	.py_thread_state = {
		.next = 8,
		.interp = 16,
		.frame = 24,
		.thread_id = 176,
		.native_thread_id = -1,
		.cframe = -1,
	},
	.py_tuple_object = {
		.ob_item = 24,
	},
	.py_type_object = {
		.tp_name = 24,
	},
	.py_interpreter_frame = {
		.owner = -1,
	},
};

static inline __attribute__((always_inline)) __u32 read_symbol(void *frame_ptr, void *code_ptr, symbol_t *symbol) {
	void *ptr;
	bpf_probe_read_user(&ptr, sizeof(ptr), code_ptr + py_offsets.py_code_object.co_varnames);
	bpf_probe_read_user(&ptr, sizeof(ptr), ptr + py_offsets.py_tuple_object.ob_item);
	bpf_probe_read_user_str(&symbol->method_name, sizeof(symbol->method_name), ptr + py_offsets.py_string.data);

	char self_str[4] = "self";
	char cls_str[4] = "cls";
	bool first_self = *(__s32 *)symbol->method_name == *(__s32 *)self_str;
	bool first_cls = *(__s32 *)symbol->method_name == *(__s32 *)cls_str;

	if (first_self || first_cls) {
		bpf_probe_read_user(&ptr, sizeof(ptr), frame_ptr + py_offsets.py_frame_object.f_localsplus);
		if (first_self) {
			bpf_probe_read_user(&ptr, sizeof(ptr), ptr + py_offsets.py_object.ob_type);
		}
		bpf_probe_read_user(&ptr, sizeof(ptr), ptr + py_offsets.py_type_object.tp_name);
		bpf_probe_read_user_str(&symbol->class_name, sizeof(symbol->class_name), ptr);
	}

	bpf_probe_read_user(&ptr, sizeof(ptr), code_ptr + py_offsets.py_code_object.co_filename);
	bpf_probe_read_user_str(&symbol->path, sizeof(symbol->path), ptr + py_offsets.py_string.data);

	bpf_probe_read_user(&ptr, sizeof(ptr), code_ptr + py_offsets.py_code_object.co_name);
	bpf_probe_read_user_str(&symbol->method_name, sizeof(symbol->method_name), ptr + py_offsets.py_string.data);

	__u32 lineno;
	bpf_probe_read_user(&lineno, sizeof(lineno), code_ptr + py_offsets.py_code_object.co_firstlineno);

	return lineno;
}

static inline __attribute__((always_inline)) __u32 get_symbol_id(symbol_t *symbol) {
	__u32 *found_id = bpf_map_lookup_elem(&__python_symbols, symbol);
	if (found_id) {
		return *found_id;
	}

	__u32 zero = 0;
	__u32 *sym_idx = bpf_map_lookup_elem(&__python_symbol_index, &zero);
	if (sym_idx == NULL) {
		return 0;
	}

	__u32 id = *sym_idx * 32 + bpf_get_smp_processor_id();
	*sym_idx += 1;

	int err = bpf_map_update_elem(&__python_symbols, symbol, &id, BPF_ANY);
	if (err) {
		return 0;
	}
	return id;
}

static inline __attribute__((always_inline)) __u64 hash_stack(stack_trace_t *stack) {
	const __u64 m = 0xc6a4a7935bd1e995LLU;
	const int r = 47;
	__u64 hash = stack->len * m;

#pragma unroll
	for (int i = 0; i < MAX_STACK_DEPTH; i++) {
		if (i >= stack->len) {
			break;
		}

		__u64 k = stack->addrs[i];

		k *= m;
		k ^= k >> r;
		k *= m;

		hash ^= k;
		hash *= m;
	}

	return hash;
}

/*
 * Used for communication between user space and BPF to control the
 * switching between buffer a and buffer b.
 */
MAP_ARRAY(profiler_state_map, __u32, __u64, PROFILER_CNT)

static inline __attribute__((always_inline)) int get_stack_and_output_perf(void *ctx, unwind_state_t *state)
{
	__u32 count_idx;

	count_idx = TRANSFER_CNT_IDX;
	__u64 *transfer_count_ptr = profiler_state_map__lookup(&count_idx);

	count_idx = SAMPLE_CNT_A_IDX;
	__u64 *sample_count_a_ptr = profiler_state_map__lookup(&count_idx);

	count_idx = SAMPLE_CNT_B_IDX;
	__u64 *sample_count_b_ptr = profiler_state_map__lookup(&count_idx);

	count_idx = SAMPLE_CNT_DROP;
	__u64 *drop_count_ptr = profiler_state_map__lookup(&count_idx);

	count_idx = SAMPLE_ITER_CNT_MAX;
	__u64 *iter_count_ptr = profiler_state_map__lookup(&count_idx);

	count_idx = OUTPUT_CNT_IDX;
	__u64 *output_count_ptr = profiler_state_map__lookup(&count_idx);

	count_idx = ERROR_IDX;
	__u64 *error_count_ptr = profiler_state_map__lookup(&count_idx);

	if (transfer_count_ptr == NULL || sample_count_a_ptr == NULL ||
	    sample_count_b_ptr == NULL || drop_count_ptr == NULL ||
	    iter_count_ptr == NULL || error_count_ptr == NULL ||
	    output_count_ptr == NULL) {
		count_idx = ERROR_IDX;
		__u64 err_val = 1;
		profiler_state_map__update(&count_idx, &err_val);
		return 0;
	}

	struct stack_trace_key_t *key = &state->key;

	/*
	 * Note:
	 * ------------------------------------------------------
	 * int bpf_get_stackid(struct pt_reg *ctx,
	 *                     struct bpf_map *map, u64 flags);
	 * define in include/uapi/linux/bpf.h, implementation in
	 * file "./kernel/bpf/stackmap.c"
	 *
	 * Flags **BPF_F_REUSE_STACKID** If two different stacks
	 * hash into the same *stackid*, discard the old one. Do
	 * not set this flag, we want to return the error(-EEXIST)
	 * normally for counting purposes.
	 *
	 * return
	 *    -EFAULT (couldn't fetch the stack trace)
	 *    -EEXIST (duplicate value of *stackid*) 
	 */

	__u64 sample_count = 0;
	if (!((*transfer_count_ptr) & 0x1ULL)) {
		key->kernstack = bpf_get_stackid(ctx, &NAME(stack_map_a),
						KERN_STACKID_FLAGS);
		if (key->dwarfstack == 0) {
			key->userstack = bpf_get_stackid(ctx, &NAME(stack_map_a),
							USER_STACKID_FLAGS);
			if (-EEXIST == key->userstack)
				__sync_fetch_and_add(drop_count_ptr, 1);
		}

		if (-EEXIST == key->kernstack)
			__sync_fetch_and_add(drop_count_ptr, 1);

		if (key->userstack < 0 && key->dwarfstack == 0 && key->kernstack < 0)
			return 0;

		sample_count = *sample_count_a_ptr;
		__sync_fetch_and_add(sample_count_a_ptr, 1);

		if (bpf_perf_event_output(ctx,
					  &NAME(profiler_output_a),
					  BPF_F_CURRENT_CPU, key, sizeof(struct stack_trace_key_t)))
			__sync_fetch_and_add(error_count_ptr, 1);
		else
			__sync_fetch_and_add(output_count_ptr, 1);

	} else {
		key->kernstack = bpf_get_stackid(ctx, &NAME(stack_map_b),
						KERN_STACKID_FLAGS);
		if (key->dwarfstack == 0) {
			key->userstack = bpf_get_stackid(ctx, &NAME(stack_map_b),
							USER_STACKID_FLAGS);
			if (-EEXIST == key->userstack)
				__sync_fetch_and_add(drop_count_ptr, 1);
		}

		if (-EEXIST == key->kernstack)
			__sync_fetch_and_add(drop_count_ptr, 1);

		if (key->userstack < 0 && key->dwarfstack == 0 && key->kernstack < 0)
			return 0;

		sample_count = *sample_count_b_ptr;
		__sync_fetch_and_add(sample_count_b_ptr, 1);

		if (bpf_perf_event_output(ctx,
					  &NAME(profiler_output_b),
					  BPF_F_CURRENT_CPU, key, sizeof(struct stack_trace_key_t)))
			__sync_fetch_and_add(error_count_ptr, 1);
		else
			__sync_fetch_and_add(output_count_ptr, 1);
	}

	/*
	 * Each iteration in user mode sets the sample_count to 0. If
	 * sample_count > 0, it means that the user mode program is
	 * currently in the process of iteration and has not completed
	 * the stringifier task. If sample_count is too large, it is
	 * likely to cause stack-trace loss of records. We hope to set
	 * a larger value for STACK_MAP_ENTRIES to ensure that data is
	 * not lost. The implementation method requires calculating the
	 * maximum value of the stackmap during the loading phase and
	 * resetting it.
	 *
	 * Record the maximum sample count for each iteration.
	 */
	if (sample_count > *iter_count_ptr)
		*iter_count_ptr = sample_count;

	return 0;
}

static inline __attribute__((always_inline)) bool in_kernel(__u64 ip) {
    return ip & (1UL << 63);
}

static inline __attribute__((always_inline)) void add_frame(stack_trace_t *stack, __u64 frame) {
    __u64 len = stack->len;
    if (len >= 0 && len < MAX_STACK_DEPTH) {
        stack->addrs[len] = frame;
        stack->len++;
    }
}

SEC("perf_event")
int bpf_perf_event(struct bpf_perf_event_data *ctx)
{
	__u32 count_idx = ENABLE_IDX;
	__u64 *enable_ptr = profiler_state_map__lookup(&count_idx);

	if (enable_ptr == NULL) {
		count_idx = ERROR_IDX;
		__u64 err_val = 1;
		profiler_state_map__update(&count_idx, &err_val);
		return 0;
	}

	if (unlikely(*enable_ptr == 0))
		return 0;

	__u64 id = bpf_get_current_pid_tgid();

	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}
	__builtin_memset(state, 0, sizeof(unwind_state_t));

	struct stack_trace_key_t *key = &state->key;
	key->tgid = id >> 32;
	key->pid = (__u32) id;

	/*
	 * CPU idle stacks will not be collected.
	 */
	if (key->tgid == key->pid && key->pid == 0) {
		return 0;
	}

	key->cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(&key->comm, sizeof(key->comm));
	key->timestamp = bpf_ktime_get_ns();

	if (dwarf_shard_table__lookup(&key->tgid) != NULL) {
		#if 0
  		bpf_user_pt_regs_t *regs = &ctx->regs;
  		if (in_kernel(PT_REGS_IP(regs))) {
  			// TODO: fix in kernel events
  		    return 0;
  		} else {
  		  	// in userspace
  		  	state->regs.ip = PT_REGS_IP(regs);
  		  	state->regs.sp = PT_REGS_SP(regs);
  		  	state->regs.bp = PT_REGS_FP(regs);
  		}
	    add_frame(&state->stack, state->regs.ip);
		bpf_tail_call(ctx, &NAME(progs_jmp_perf_map), PROG_DWARF_UNWIND_IDX);
		#endif
		return 0;
	}

	return get_stack_and_output_perf(ctx, state);
}

MAP_HASH(python_thread_state_map, __u32, __u64, 65536)

PROGPE(python_frame_ptr)(struct bpf_perf_event_data *ctx) {
	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}

	__u64 *tstate_addr = python_tstate_addr__lookup(&zero);
	if (tstate_addr == NULL) {
		goto finish;
	}
	if (bpf_probe_read_user(&state->thread_state, sizeof(void *), (void *)*tstate_addr) != 0) {
		goto finish;
	}
	if (state->thread_state != NULL) {
		python_thread_state_map__update(&state->key.tgid, (__u64 *)&state->thread_state);
	} else {
		__u64 *entry = python_thread_state_map__lookup(&state->key.tgid);
		if (entry) {
			state->thread_state = (void *)*entry;
		} else {
			goto finish;
		}
	}

	if (bpf_probe_read_user(&state->key.itid, sizeof(__u32), state->thread_state + py_offsets.py_thread_state.thread_id) != 0) {
		goto finish;
	}

	if (bpf_probe_read_user(&state->frame_ptr, sizeof(void *), state->thread_state + py_offsets.py_thread_state.frame) != 0) {
		goto finish;
	}

	bpf_tail_call(ctx, &NAME(progs_jmp_perf_map), PROG_PYTHON_WALK_STACK_IDX);

finish:
	return get_stack_and_output_perf(ctx, state);
}

PROGPE(python_walk_stack)(struct bpf_perf_event_data *ctx) {
	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}

	if (state->frame_ptr == NULL) {
		goto output;
	}

	symbol_t symbol;

#pragma unroll
	for (int i = 0; i < STACK_FRAMES_PER_RUN; i++) {
		void *code_ptr = 0;
		if (bpf_probe_read_user(&code_ptr, sizeof(code_ptr), state->frame_ptr + py_offsets.py_frame_object.f_code) != 0) {
			goto output;
		}
		if (code_ptr == NULL) {
			goto output;
		}

		__builtin_memset(&symbol, 0, sizeof(symbol));
		__u64 lineno = read_symbol(state->frame_ptr, code_ptr, &symbol);
		if (lineno == 0) {
			goto output;
		}
		__u64 symbol_id = get_symbol_id(&symbol);
		add_frame(&state->stack, (lineno << 32) | symbol_id);

		if (bpf_probe_read_user(&state->frame_ptr, sizeof(void *), state->frame_ptr + py_offsets.py_frame_object.f_back) != 0) {
			goto output;
		}
		if (!state->frame_ptr) {
			goto output;
		}
	}

	if (++state->runs < STACK_PROG_MAX_RUN) {
		bpf_tail_call(ctx, &NAME(progs_jmp_perf_map), PROG_PYTHON_WALK_STACK_IDX);
	}

output:

	if (state->stack.len > 0) {
		state->key.intpstack = hash_stack(&state->stack);
		python_stack__update(&state->key.intpstack, &state->stack);
	}
	bpf_tail_call(ctx, &NAME(progs_jmp_perf_map), PROG_PYTHON_PERF_OUTPUT_IDX);
	return 0;
}

PROGPE(python_perf_output)(struct bpf_perf_event_data *ctx) {
	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}
	return get_stack_and_output_perf(ctx, state);
}

static inline __attribute__((always_inline)) __u32 find_shard_id(shard_info_list_t *shard_info, __u64 pc) {
#pragma unroll
	for (int i = 0; i < 32; i++) {
		shard_info_t *si = shard_info->info + i;
		if (si->pc_min <= pc && si->pc_max > pc) {
			return si->id;
		}
	}
	return 0xFFFFFFFF;
}

#define BSEARCH_INDEX_INVALID 0xFFFFFFFE
#define BSEARCH_NOT_FOUND     0xFFFFFFFF

static inline __attribute__((always_inline)) __u32 search_uentry(unwind_entry_shard_t *shard, __u64 pc) {
	__u32 i = 0, j = shard->len;
	__u32 found = BSEARCH_NOT_FOUND;

#pragma unroll
	for (int loops = 0; loops < 19; loops++) {
		if (i >= j) {
			return found;
		}
		__u32 mid = (i + j) / 2;
		if (mid < 0 || mid >= ENTRIES_PER_SHARD) {
			return BSEARCH_INDEX_INVALID;
		}
		if (shard->entries[mid].pc <= pc) {
			found = mid;
			i = mid + 1;
		} else {
			j = mid;
		}
	}
	return BSEARCH_NOT_FOUND;
}

PROGPE(dwarf_unwind)(struct bpf_perf_event_data *ctx) {
	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}

	shard_info_list_t *shard_info = dwarf_shard_table__lookup(&state->key.tgid);
	if (shard_info == NULL) {
		return 0;
	}

	reg_t *regs = &state->regs;

#pragma unroll
	for (int i = 0; i < STACK_FRAMES_PER_RUN; i++) {
		// bpf_debug("frame#%d", state->stack.len);
		// bpf_debug("ip=%lx bp=%lx sp=%lx", regs->ip, regs->bp, regs->sp);
		__u32 shard_id = find_shard_id(shard_info, regs->ip);
		if (shard_id >= 32) {
			goto finish;
		}
		unwind_entry_shard_t *shard = dwarf_unwind_table__lookup(&shard_id);
		if (shard == NULL) {
			return 0;
		}
	    __u32 index = search_uentry(shard, regs->ip);
	    if (index == BSEARCH_NOT_FOUND) {
	    	goto finish;
	    }
		if (index < 0 || index >= ENTRIES_PER_SHARD) {
			return 0;
		}
		__u64 cfa = 0;
		unwind_entry_t *entry = &shard->entries[index];
		switch (entry->cfa_type) {
		case CFA_TYPE_RBP_OFFSET:
			if (entry->cfa_offset < 0) {
				cfa = regs->bp - ((-entry->cfa_offset) << 3);
			} else {
				cfa = regs->bp + (entry->cfa_offset << 3);
			}
			break;
  	    case CFA_TYPE_RSP_OFFSET:
			if (entry->cfa_offset < 0) {
				cfa = regs->sp - ((-entry->cfa_offset) << 3);
			} else {
				cfa = regs->sp + (entry->cfa_offset << 3);
			}
  	    	break;
  	    default:
  	    	bpf_debug("unhandled cfa_type %d", entry->cfa_type);
  	    	return 0;
		}
		if (bpf_probe_read_user(&regs->ip, sizeof(__u64), (void *)(cfa - 8)) != 0) {
  	    	bpf_debug("read ip failed");
			return 0;
		}
  		__u64 rbp_addr = cfa;
		switch (entry->rbp_type) {
		case REG_TYPE_UNDEFINED: case REG_TYPE_SAME_VALUE:
        	break;
  		case REG_TYPE_OFFSET:
			if (entry->rbp_offset < 0) {
				rbp_addr -= (-entry->rbp_offset) << 3;
			} else {
				rbp_addr += (entry->rbp_offset) << 3;
			}
			if (bpf_probe_read_user(&regs->bp, sizeof(__u64), (void *)rbp_addr) != 0) {
  	    		bpf_debug("read bp failed");
				return 0;
			}
  			break;
  		case REG_TYPE_UNSUPPORTED:
  	    	bpf_debug("unsupported rpb_type %d", entry->rbp_type);
  			return 0;
		}
		regs->sp = cfa;
	    add_frame(&state->stack, regs->ip);
	}

	if (++state->runs < STACK_PROG_MAX_RUN) {
		bpf_tail_call(ctx, &NAME(progs_jmp_perf_map), PROG_DWARF_UNWIND_IDX);
	}

finish:
	state->runs = 0;
	if (state->stack.len > 0) {
		state->key.dwarfstack = hash_stack(&state->stack);
		python_stack__update(&state->key.dwarfstack, &state->stack);
		__builtin_memset(&state->stack, 0, sizeof(state->stack));
	}
	bpf_tail_call(ctx, &NAME(progs_jmp_perf_map), PROG_PYTHON_FRAME_PTR_IDX);
	return 0;
}

SEC("uretprobe/python_save_tstate")
int uprobe_python_save_tstate(struct pt_regs *ctx) {
    long ret = PT_REGS_RC(ctx);
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

	__u64 *addr = python_thread_state_map__lookup(&tgid);
    if (addr) {
        *addr = ret;
    } else {
        python_thread_state_map__update(&tgid, (__u64*) &ret);
    }
	return 0;
}

typedef struct {
    void *address;
    __u64 size;
    __u64 call_time;
    __u64 rip;
} malloc_data_t;

MAP_HASH(cuda_malloc_info, __u32, malloc_data_t, 65536)

SEC("uprobe/cuda_malloc")
int uprobe_cuda_malloc(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    void *address = (void *) PT_REGS_PARM1(ctx);
    __u64 size = (__u64) PT_REGS_PARM2(ctx);
    malloc_data_t *data = cuda_malloc_info__lookup(&tgid);
    __u64 call_time = bpf_ktime_get_ns();

    if (data) {
        data->address = address;
        data->size = size;
        data->call_time = call_time;
        data->rip = PT_REGS_IP(ctx);
    } else {
        malloc_data_t newdata = { .address = address, .size = size, .call_time = call_time, .rip = PT_REGS_IP(ctx) };
        cuda_malloc_info__update(&tgid, &newdata);
    }

    return 0;
}

MAP_PERF_EVENT(cuda_memory_output, int, __u32, MAX_CPU)

SEC("uretprobe/cuda_malloc")
int uretprobe_cuda_malloc(struct pt_regs *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    long ret = PT_REGS_RC(ctx);
    if (ret != 0) {
        return 0;
    }

    malloc_data_t *data = cuda_malloc_info__lookup(&tgid);
    if (data == NULL) {
        return 0;
    }
    cuda_malloc_info__delete(&tgid);

	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}
	__builtin_memset(state, 0, sizeof(unwind_state_t));

	struct stack_trace_key_t *key = &state->key;
	key->tgid = id >> 32;
	key->pid = (__u32) id;

	/*
	 * CPU idle stacks will not be collected.
	 */
	if (key->tgid == key->pid && key->pid == 0) {
		return 0;
	}

	key->cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(&key->comm, sizeof(key->comm));
	key->timestamp = bpf_ktime_get_ns();

	bpf_probe_read_user(&key->mem_addr, sizeof(__u64), (void *)data->address);
	key->mem_size = (__u64) data->size;

    // add one frame for cudaMalloc
    // native unwinding start from uretprobe, which has the reg state after cudaMalloc return
    add_frame(&state->stack, data->rip);

	state->regs.ip = PT_REGS_IP(ctx);
	state->regs.sp = PT_REGS_SP(ctx);
	state->regs.bp = PT_REGS_FP(ctx);
    add_frame(&state->stack, state->regs.ip);
    bpf_tail_call(ctx, &NAME(progs_jmp_uprobe_map), PROG_DWARF_UNWIND_IDX);

    return 0;
}

SEC("uprobe/cuda_free")
int uprobe_cuda_free(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();

	void *addr = (void *) PT_REGS_PARM1(ctx);

	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}
	__builtin_memset(state, 0, sizeof(unwind_state_t));

	struct stack_trace_key_t *key = &state->key;
	key->tgid = id >> 32;
	key->pid = (__u32) id;

	/*
	 * CPU idle stacks will not be collected.
	 */
	if (key->tgid == key->pid && key->pid == 0) {
		return 0;
	}

	key->cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(&key->comm, sizeof(key->comm));
	key->timestamp = bpf_ktime_get_ns();

	key->mem_addr = (__u64) addr;

	bpf_perf_event_output(ctx, &NAME(cuda_memory_output), BPF_F_CURRENT_CPU, &state->key, sizeof(state->key));

    return 0;
}

PROGKP(dwarf_unwind)(void *ctx) {
	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}

	shard_info_list_t *shard_info = dwarf_shard_table__lookup(&state->key.tgid);
	if (shard_info == NULL) {
		bpf_perf_event_output(ctx, &NAME(cuda_memory_output), BPF_F_CURRENT_CPU, &state->key, sizeof(state->key));
		return 0;
	}

	reg_t *regs = &state->regs;

#pragma unroll
	for (int i = 0; i < STACK_FRAMES_PER_RUN; i++) {
		// bpf_debug("frame#%d", state->stack.len);
		// bpf_debug("ip=%lx bp=%lx sp=%lx", regs->ip, regs->bp, regs->sp);
		__u32 shard_id = find_shard_id(shard_info, regs->ip);
		if (shard_id >= 32) {
			goto finish;
		}
		unwind_entry_shard_t *shard = dwarf_unwind_table__lookup(&shard_id);
		if (shard == NULL) {
			goto finish;
		}
	    __u32 index = search_uentry(shard, regs->ip);
	    if (index == BSEARCH_NOT_FOUND) {
	    	goto finish;
	    }
		if (index < 0 || index >= ENTRIES_PER_SHARD) {
			goto finish;
		}
		__u64 cfa = 0;
		unwind_entry_t *entry = &shard->entries[index];
		switch (entry->cfa_type) {
		case CFA_TYPE_RBP_OFFSET:
			if (entry->cfa_offset < 0) {
				cfa = regs->bp - ((-entry->cfa_offset) << 3);
			} else {
				cfa = regs->bp + (entry->cfa_offset << 3);
			}
			break;
  	    case CFA_TYPE_RSP_OFFSET:
			if (entry->cfa_offset < 0) {
				cfa = regs->sp - ((-entry->cfa_offset) << 3);
			} else {
				cfa = regs->sp + (entry->cfa_offset << 3);
			}
  	    	break;
  	    default:
  	    	bpf_debug("unhandled cfa_type %d", entry->cfa_type);
			goto finish;
		}
		if (bpf_probe_read_user(&regs->ip, sizeof(__u64), (void *)(cfa - 8)) != 0) {
  	    	bpf_debug("read ip failed");
			goto finish;
		}
  		__u64 rbp_addr = cfa;
		switch (entry->rbp_type) {
		case REG_TYPE_UNDEFINED: case REG_TYPE_SAME_VALUE:
        	break;
  		case REG_TYPE_OFFSET:
			if (entry->rbp_offset < 0) {
				rbp_addr -= (-entry->rbp_offset) << 3;
			} else {
				rbp_addr += (entry->rbp_offset) << 3;
			}
			if (bpf_probe_read_user(&regs->bp, sizeof(__u64), (void *)rbp_addr) != 0) {
  	    		bpf_debug("read bp failed");
				goto finish;
			}
  			break;
  		case REG_TYPE_UNSUPPORTED:
  	    	bpf_debug("unsupported rpb_type %d", entry->rbp_type);
			goto finish;
		}
		regs->sp = cfa;
	    add_frame(&state->stack, regs->ip);
	}

	if (++state->runs < STACK_PROG_MAX_RUN) {
		bpf_tail_call(ctx, &NAME(progs_jmp_uprobe_map), PROG_DWARF_UNWIND_IDX);
	}

finish:
	state->runs = 0;
	if (state->stack.len > 0) {
		state->key.dwarfstack = hash_stack(&state->stack);
		python_stack__update(&state->key.dwarfstack, &state->stack);
		__builtin_memset(&state->stack, 0, sizeof(state->stack));
	}
	bpf_tail_call(ctx, &NAME(progs_jmp_uprobe_map), PROG_PYTHON_FRAME_PTR_IDX);
	return 0;
}

PROGKP(python_frame_ptr)(void *ctx) {
	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}

	__u64 *tstate_addr = python_tstate_addr__lookup(&zero);
	if (tstate_addr == NULL) {
		goto finish;
	}
	if (bpf_probe_read_user(&state->thread_state, sizeof(void *), (void *)*tstate_addr) != 0) {
		goto finish;
	}
	if (state->thread_state != NULL) {
		python_thread_state_map__update(&state->key.tgid, (__u64 *)&state->thread_state);
	} else {
		__u64 *entry = python_thread_state_map__lookup(&state->key.tgid);
		if (entry) {
			state->thread_state = (void *)*entry;
		} else {
			goto finish;
		}
	}

	if (bpf_probe_read_user(&state->key.itid, sizeof(__u32), state->thread_state + py_offsets.py_thread_state.thread_id) != 0) {
		goto finish;
	}

	if (bpf_probe_read_user(&state->frame_ptr, sizeof(void *), state->thread_state + py_offsets.py_thread_state.frame) != 0) {
		goto finish;
	}

	bpf_tail_call(ctx, &NAME(progs_jmp_uprobe_map), PROG_PYTHON_WALK_STACK_IDX);

finish:
	bpf_perf_event_output(ctx, &NAME(cuda_memory_output), BPF_F_CURRENT_CPU, &state->key, sizeof(state->key));
	return 0;
}

PROGKP(python_walk_stack)(void *ctx) {
	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}

	if (state->frame_ptr == NULL) {
		goto output;
	}

	symbol_t symbol;

#pragma unroll
	for (int i = 0; i < STACK_FRAMES_PER_RUN; i++) {
		void *code_ptr = 0;
		if (bpf_probe_read_user(&code_ptr, sizeof(code_ptr), state->frame_ptr + py_offsets.py_frame_object.f_code) != 0) {
			goto output;
		}
		if (code_ptr == NULL) {
			goto output;
		}

		__builtin_memset(&symbol, 0, sizeof(symbol));
		__u64 lineno = read_symbol(state->frame_ptr, code_ptr, &symbol);
		if (lineno == 0) {
			goto output;
		}
		__u64 symbol_id = get_symbol_id(&symbol);
		add_frame(&state->stack, (lineno << 32) | symbol_id);

		if (bpf_probe_read_user(&state->frame_ptr, sizeof(void *), state->frame_ptr + py_offsets.py_frame_object.f_back) != 0) {
			goto output;
		}
		if (!state->frame_ptr) {
			goto output;
		}
	}

	if (++state->runs < STACK_PROG_MAX_RUN) {
		bpf_tail_call(ctx, &NAME(progs_jmp_uprobe_map), PROG_PYTHON_WALK_STACK_IDX);
	}

output:

	if (state->stack.len > 0) {
		state->key.intpstack = hash_stack(&state->stack);
		python_stack__update(&state->key.intpstack, &state->stack);
	}

	bpf_perf_event_output(ctx, &NAME(cuda_memory_output), BPF_F_CURRENT_CPU, &state->key, sizeof(state->key));
	return 0;
}

#if 0
SEC("uprobe/cuda_memcpy_async")
int uprobe_cuda_memcpy_async(struct pt_regs *ctx)
{
    int kind = PT_REGS_PARM4(ctx);
    size_t count = PT_REGS_PARM5(ctx);

    bpf_debug("cudaMemcpyAsync copy %d %d bytes", kind, count);
    return 0;
}
#endif
