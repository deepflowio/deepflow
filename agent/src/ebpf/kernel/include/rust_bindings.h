#ifndef RUST_BINDINGS_H
#define RUST_BINDINGS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


#define ENTRIES_PER_SHARD 250000

#define MAX_STACK_DEPTH (STACK_PROG_MAX_RUN * STACK_FRAMES_PER_RUN)

#define STACK_FRAMES_PER_RUN 16

#define STACK_PROG_MAX_RUN 5

enum CfaType {
  CFA_TYPE_RBP_OFFSET,
  CFA_TYPE_RSP_OFFSET,
  CFA_TYPE_EXPRESSION,
  CFA_TYPE_UNSUPPORTED,
};
typedef uint8_t CfaType;

enum RegType {
  REG_TYPE_UNDEFINED,
  REG_TYPE_SAME_VALUE,
  REG_TYPE_OFFSET,
  REG_TYPE_UNSUPPORTED,
};
typedef uint8_t RegType;

typedef struct shard_info_t {
  int32_t id;
  uint64_t pc_min;
  uint64_t pc_max;
} shard_info_t;

typedef struct shard_info_list_t {
  struct shard_info_t info[40];
} shard_info_list_t;

typedef struct unwind_entry_t {
  uint64_t pc;
  CfaType cfa_type;
  RegType rbp_type;
  int16_t cfa_offset;
  int16_t rbp_offset;
} unwind_entry_t;

typedef struct unwind_entry_shard_t {
  uint32_t len;
  struct unwind_entry_t entries[ENTRIES_PER_SHARD];
} unwind_entry_shard_t;

typedef struct stack_trace_t {
  uint64_t len;
  uint64_t addrs[MAX_STACK_DEPTH];
} stack_trace_t;

void merge_stacks(int8_t *trace_str, size_t len, const int8_t *i_trace, const int8_t *u_trace);

void poll_cuda_memory_output(int32_t output_fd, int32_t stack_map_fd, int32_t symbol_map_fd);

#endif /* RUST_BINDINGS_H */
