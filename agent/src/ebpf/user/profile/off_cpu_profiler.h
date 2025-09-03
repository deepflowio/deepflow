/*
 * Off-CPU Profiler User-Space Header
 * Copyright (c) 2024 Yunshan Networks
 */

#ifndef DF_OFF_CPU_PROFILER_H
#define DF_OFF_CPU_PROFILER_H

#include <stdint.h>
#include <stdbool.h>
#include "../tracer.h"
#include "profile_common.h"

/* Off-CPU profiler configuration */
struct off_cpu_profiler_config {
    bool enabled;                    // Enable/disable off-CPU profiling
    uint64_t min_block_time_ns;     // Minimum blocking time to record (default: 50μs)
    uint32_t max_events;            // Maximum concurrent events to track
    uint32_t sample_period;         // Sample period in nanoseconds (0 = all events)
    bool track_wakers;              // Track processes that wake up blocked processes
    bool classify_block_reasons;    // Classify different blocking reasons
    bool enable_stack_traces;       // Capture stack traces for blocked processes
    uint32_t max_stack_depth;       // Maximum stack depth to capture
};

/* Off-CPU event statistics */
struct off_cpu_profiler_stats {
    uint64_t total_block_events;         // Total blocking events recorded
    uint64_t total_block_time_ns;        // Total blocking time across all processes
    uint64_t events_by_reason[8];        // Events count by blocking reason
    uint64_t avg_block_time_ns;          // Average blocking time
    uint64_t max_block_time_ns;          // Maximum blocking time observed
    uint64_t min_block_time_ns;          // Minimum blocking time observed
    uint64_t stack_trace_failures;       // Failed stack trace captures
    uint64_t events_dropped;             // Events dropped due to rate limiting
    uint64_t pending_events;             // Currently pending (blocked) events
    uint64_t cache_hits;                 // Stack trace cache hits
    uint64_t cache_misses;               // Stack trace cache misses
};

/* Block reason names for reporting */
extern const char* off_cpu_block_reason_names[];

/* Off-CPU profiler context */
struct off_cpu_profiler_context {
    struct profiler_context base;           // Base profiler context
    struct off_cpu_profiler_config config; // Configuration
    struct off_cpu_profiler_stats stats;   // Runtime statistics
    void *callback_ctx;                     // Callback context
    uint64_t last_stats_time;              // Last statistics update time
    bool initialized;                       // Initialization status
};

/* Function declarations */

/**
 * Initialize off-CPU profiler with given configuration
 * @param config Configuration parameters
 * @param callback_ctx Context for callback functions
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_init(const struct off_cpu_profiler_config *config, 
                         void *callback_ctx);

/**
 * Start off-CPU profiling
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_start(void);

/**
 * Stop off-CPU profiling
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_stop(void);

/**
 * Update off-CPU profiler configuration at runtime
 * @param config New configuration
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_set_config(const struct off_cpu_profiler_config *config);

/**
 * Get current off-CPU profiler statistics
 * @param stats Output buffer for statistics
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_get_stats(struct off_cpu_profiler_stats *stats);

/**
 * Reset off-CPU profiler statistics
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_reset_stats(void);

/**
 * Set minimum blocking time threshold
 * @param min_time_ns Minimum time in nanoseconds
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_set_min_block_time(uint64_t min_time_ns);

/**
 * Enable or disable specific blocking reason tracking
 * @param reason Block reason type (0-7)
 * @param enabled True to enable, false to disable
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_set_reason_enabled(uint32_t reason, bool enabled);

/**
 * Add a process to off-CPU profiling
 * @param pid Process ID to profile
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_add_process(uint32_t pid);

/**
 * Remove a process from off-CPU profiling  
 * @param pid Process ID to stop profiling
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_remove_process(uint32_t pid);

/**
 * Process off-CPU events from eBPF (internal callback)
 * @param ctx Context
 * @param data Event data from eBPF
 * @param data_size Size of event data
 */
void off_cpu_profiler_process_event(void *ctx, void *data, int data_size);

/**
 * Export off-CPU profiling statistics to JSON
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @return 0 on success, negative on error
 */
int off_cpu_profiler_export_stats_json(char *buffer, size_t buffer_size);

/**
 * Get human-readable name for blocking reason
 * @param reason Block reason type
 * @return String name of the reason
 */
const char* off_cpu_profiler_get_reason_name(uint32_t reason);

/**
 * Cleanup off-CPU profiler resources
 */
void off_cpu_profiler_cleanup(void);

#endif /* DF_OFF_CPU_PROFILER_H */