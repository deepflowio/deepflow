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
struct bpf_map_def SEC("maps") __python_symbols = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	__BPF_MAP_DEF(symbol_t, __u32, 512),
};
MAP_PERARRAY(heap, __u32, unwind_state_t, 1)
MAP_PERARRAY(python_symbol_index, __u32, __u32, 1)
MAP_HASH(python_stack, __u64, stack_trace_t, STACK_MAP_ENTRIES)

static inline __attribute__((always_inline)) bool comm_eq(char *a, char *b) {
#pragma unroll
	for (int i = 0; i < TASK_COMM_LEN; i++) {
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
		.f_lineno = 108,
		.f_localsplus = 360,
	},
	.py_object = {
		.ob_type = 8,
	},
	.py_string = {
		.data = 48,
		.size = 16,
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

		__u64 k = stack->addresses[i];

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

static inline __attribute__((always_inline)) int get_stack_and_output_perf(struct bpf_perf_event_data *ctx, unwind_state_t *state)
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
		key->userstack = bpf_get_stackid(ctx, &NAME(stack_map_a),
						USER_STACKID_FLAGS);

		if (-EEXIST == key->kernstack)
			__sync_fetch_and_add(drop_count_ptr, 1);

		if (-EEXIST == key->userstack)
			__sync_fetch_and_add(drop_count_ptr, 1);

		if (key->userstack < 0 && key->kernstack < 0)
			return 0;

		if (state->stack.len > 0) {
			key->intpstack = hash_stack(&state->stack);
			python_stack__update(&key->intpstack, &state->stack);
		}

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
		key->userstack = bpf_get_stackid(ctx, &NAME(stack_map_b),
						USER_STACKID_FLAGS);

		if (-EEXIST == key->kernstack)
			__sync_fetch_and_add(drop_count_ptr, 1);

		if (-EEXIST == key->userstack)
			__sync_fetch_and_add(drop_count_ptr, 1);

		if (key->userstack < 0 && key->kernstack < 0)
			return 0;

		if (state->stack.len > 0) {
			key->intpstack = hash_stack(&state->stack);
			python_stack__update(&key->intpstack, &state->stack);
		}

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
	if (key->tgid == key->pid && key->pid == 0)
		return 0;

	key->cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(&key->comm, sizeof(key->comm));
	key->timestamp = bpf_ktime_get_ns();

	if (comm_eq(key->comm, "python3")) {
		bpf_tail_call(ctx, &NAME(progs_jmp_perf_map), PROG_PYTHON_FRAME_PTR_IDX);
	}

	return get_stack_and_output_perf(ctx, state);
}

PROGPE(python_frame_ptr)(struct bpf_perf_event_data *ctx) {
	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}

	__u64 thread_state_addr = 140737353904984;
	if (bpf_probe_read_user(&state->thread_state, sizeof(void *), (void *)thread_state_addr) != 0) {
		goto finish;
	}

	if (bpf_probe_read_user(&state->key.itid, sizeof(__u32), state->thread_state + py_offsets.py_thread_state.thread_id) != 0) {
		goto finish;
	}

	if (bpf_probe_read_user(&state->frame_ptr, sizeof(void *), state->thread_state + py_offsets.py_thread_state.frame) != 0) {
		goto finish;
	}

	bpf_tail_call(ctx, &NAME(progs_jmp_perf_map), PROG_PYTHON_WALK_STACK_IDX);

finish:
	return 0;
}

PROGPE(python_walk_stack)(struct bpf_perf_event_data *ctx) {
	__u32 zero = 0;
	unwind_state_t *state = heap__lookup(&zero);
	if (state == NULL) {
		return 0;
	}

	if (state->frame_ptr == NULL) {
		if (state->stack.len == 0) {
			return 0;
		}
		goto output;
	}

	symbol_t symbol;

#pragma unroll
	for (int i = 0; i < PYTHON_STACK_FRAMES_PER_RUN; i++) {
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
		__u64 cur_len = state->stack.len;
		if (cur_len >= 0 && cur_len < MAX_STACK_DEPTH) {
			state->stack.addresses[state->stack.len++] = (lineno << 32) | symbol_id;
		}

		if (bpf_probe_read_user(&state->frame_ptr, sizeof(void *), state->frame_ptr + py_offsets.py_frame_object.f_back) != 0) {
			goto output;
		}
		if (!state->frame_ptr) {
			goto output;
		}
	}

	if (state->runs++ < PYTHON_STACK_PROG_MAX_RUN) {
		bpf_tail_call(ctx, &NAME(progs_jmp_perf_map), PROG_PYTHON_WALK_STACK_IDX);
	}

output:

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
