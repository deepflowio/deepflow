/*
 * Interpreter Unwind Hook Stub (Open Source)
 */
#ifndef INTERPRETER_UNWIND_H
#define INTERPRETER_UNWIND_H

static inline __attribute__((always_inline))
int extended_interpreter_unwind(void *ctx, unwind_state_t *state, map_group_t *maps) {
    return 0;
}

static inline __attribute__((always_inline))
int extended_dwarf_after_unwind(void *ctx, unwind_state_t *state, map_group_t *maps) {
    return 0;
}

#endif /* INTERPRETER_UNWIND_H */
