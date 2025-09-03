/*
 * Off-CPU Profiler User-Space Implementation
 * Copyright (c) 2024 Yunshan Networks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>

#include "off_cpu_profiler.h"
#include "profile_common.h"
#include "../tracer.h"
#include "../log.h"
#include "../mem.h"
#include "../utils.h"
#include "../table.h"
#include "../socket.h"

/* Global off-CPU profiler context */
static struct off_cpu_profiler_context *g_off_cpu_ctx = NULL;
static pthread_mutex_t off_cpu_profiler_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Block reason names for human-readable output */
const char* off_cpu_block_reason_names[] = {
    "Unknown",
    "IO Wait",
    "Mutex Lock",
    "Sleep",
    "Futex",
    "Network",
    "Memory Allocation",
    "Other"
};

/* Default configuration */
static const struct off_cpu_profiler_config default_config = {
    .enabled = true,
    .min_block_time_ns = 50000,        // 50μs
    .max_events = 65536,
    .sample_period = 0,                // Record all events
    .track_wakers = true,
    .classify_block_reasons = true,
    .enable_stack_traces = true,
    .max_stack_depth = 64
};

/* Forward declarations */
static int setup_off_cpu_maps(struct bpf_tracer *tracer);
static int setup_off_cpu_events(struct bpf_tracer *tracer);
static void update_off_cpu_statistics(struct off_cpu_profiler_context *ctx,
                                     const struct stack_trace_key_t *event);

int off_cpu_profiler_init(const struct off_cpu_profiler_config *config,
                         void *callback_ctx)
{
    pthread_mutex_lock(&off_cpu_profiler_mutex);

    if (g_off_cpu_ctx != NULL) {
        ebpf_warning("Off-CPU profiler already initialized\n");
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return -EALREADY;
    }

    /* Allocate context */
    g_off_cpu_ctx = clib_mem_alloc_aligned("off_cpu_ctx",
                                          sizeof(struct off_cpu_profiler_context),
                                          0, NULL);
    if (!g_off_cpu_ctx) {
        ebpf_warning("Failed to allocate off-CPU profiler context\n");
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return -ENOMEM;
    }

    memset(g_off_cpu_ctx, 0, sizeof(struct off_cpu_profiler_context));

    /* Initialize configuration */
    if (config) {
        g_off_cpu_ctx->config = *config;
    } else {
        g_off_cpu_ctx->config = default_config;
    }

    g_off_cpu_ctx->callback_ctx = callback_ctx;
    g_off_cpu_ctx->last_stats_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_NAN);

    /* Initialize base profiler context */
    int ret = profiler_context_init(&g_off_cpu_ctx->base,
                                   "Off-CPU Profiler",
                                   "[OFF-CPU] ",
                                   PROFILER_TYPE_OFFCPU,
                                   g_off_cpu_ctx->config.enabled,
                                   "off_cpu_state_map",
                                   "off_cpu_stack_map_a",
                                   "off_cpu_stack_map_b",
                                   "off_cpu_custom_stack_map_a",
                                   "off_cpu_custom_stack_map_b",
                                   false,  // Process all events, not just matched
                                   true,   // Use delta time for blocking duration
                                   g_off_cpu_ctx->config.sample_period,
                                   callback_ctx);

    if (ret != 0) {
        ebpf_warning("Failed to initialize base profiler context: %d\n", ret);
        clib_mem_free(g_off_cpu_ctx);
        g_off_cpu_ctx = NULL;
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return ret;
    }

    g_off_cpu_ctx->initialized = true;

    ebpf_info("Off-CPU profiler initialized successfully\n");
    pthread_mutex_unlock(&off_cpu_profiler_mutex);

    return 0;
}

int off_cpu_profiler_start(void)
{
    pthread_mutex_lock(&off_cpu_profiler_mutex);

    if (!g_off_cpu_ctx || !g_off_cpu_ctx->initialized) {
        ebpf_warning("Off-CPU profiler not initialized\n");
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return -EINVAL;
    }

    if (!g_off_cpu_ctx->config.enabled) {
        ebpf_warning("Off-CPU profiler is disabled in configuration\n");
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return -ENODEV;
    }

    extern struct bpf_tracer *profiler_tracer;
    if (!profiler_tracer) {
        ebpf_warning("Profiler tracer not available\n");
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return -ENODEV;
    }

    /* Setup eBPF maps and events */
    int ret = setup_off_cpu_maps(profiler_tracer);
    if (ret != 0) {
        ebpf_warning("Failed to setup off-CPU eBPF maps: %d\n", ret);
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return ret;
    }

    ret = setup_off_cpu_events(profiler_tracer);
    if (ret != 0) {
        ebpf_warning("Failed to setup off-CPU events: %d\n", ret);
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return ret;
    }

    /* Enable eBPF program */
    set_bpf_run_enabled(profiler_tracer, &g_off_cpu_ctx->base, 1);

    ebpf_info("Off-CPU profiler started successfully\n");
    pthread_mutex_unlock(&off_cpu_profiler_mutex);

    return 0;
}

int off_cpu_profiler_stop(void)
{
    pthread_mutex_lock(&off_cpu_profiler_mutex);

    if (!g_off_cpu_ctx || !g_off_cpu_ctx->initialized) {
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return -EINVAL;
    }

    extern struct bpf_tracer *profiler_tracer;
    if (profiler_tracer) {
        /* Disable eBPF program */
        set_bpf_run_enabled(profiler_tracer, &g_off_cpu_ctx->base, 0);
    }

    ebpf_info("Off-CPU profiler stopped\n");
    pthread_mutex_unlock(&off_cpu_profiler_mutex);

    return 0;
}

int off_cpu_profiler_set_config(const struct off_cpu_profiler_config *config)
{
    if (!config) {
        return -EINVAL;
    }

    pthread_mutex_lock(&off_cpu_profiler_mutex);

    if (!g_off_cpu_ctx || !g_off_cpu_ctx->initialized) {
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return -EINVAL;
    }

    g_off_cpu_ctx->config = *config;

    /* Update eBPF map with new minimum block time */
    extern struct bpf_tracer *profiler_tracer;
    if (profiler_tracer) {
        if (!bpf_table_set_value(profiler_tracer, "off_cpu_state_map",
                                MINBLOCK_TIME_IDX, (void *)&config->min_block_time_ns)) {
            ebpf_warning("Failed to update minimum block time in eBPF\n");
        }
    }

    ebpf_info("Off-CPU profiler configuration updated\n");
    pthread_mutex_unlock(&off_cpu_profiler_mutex);

    return 0;
}

int off_cpu_profiler_get_stats(struct off_cpu_profiler_stats *stats)
{
    if (!stats) {
        return -EINVAL;
    }

    pthread_mutex_lock(&off_cpu_profiler_mutex);

    if (!g_off_cpu_ctx || !g_off_cpu_ctx->initialized) {
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return -EINVAL;
    }

    *stats = g_off_cpu_ctx->stats;

    pthread_mutex_unlock(&off_cpu_profiler_mutex);

    return 0;
}

int off_cpu_profiler_reset_stats(void)
{
    pthread_mutex_lock(&off_cpu_profiler_mutex);

    if (!g_off_cpu_ctx || !g_off_cpu_ctx->initialized) {
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return -EINVAL;
    }

    memset(&g_off_cpu_ctx->stats, 0, sizeof(g_off_cpu_ctx->stats));
    g_off_cpu_ctx->stats.min_block_time_ns = UINT64_MAX;
    g_off_cpu_ctx->last_stats_time = gettime(CLOCK_MONOTONIC, TIME_TYPE_NAN);

    pthread_mutex_unlock(&off_cpu_profiler_mutex);

    return 0;
}

int off_cpu_profiler_set_min_block_time(uint64_t min_time_ns)
{
    pthread_mutex_lock(&off_cpu_profiler_mutex);

    if (!g_off_cpu_ctx || !g_off_cpu_ctx->initialized) {
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return -EINVAL;
    }

    g_off_cpu_ctx->config.min_block_time_ns = min_time_ns;

    /* Update eBPF map */
    extern struct bpf_tracer *profiler_tracer;
    if (profiler_tracer) {
        if (!bpf_table_set_value(profiler_tracer, "off_cpu_state_map",
                                MINBLOCK_TIME_IDX, &min_time_ns)) {
            ebpf_warning("Failed to update minimum block time in eBPF\n");
            pthread_mutex_unlock(&off_cpu_profiler_mutex);
            return -EIO;
        }
    }

    pthread_mutex_unlock(&off_cpu_profiler_mutex);
    return 0;
}

int off_cpu_profiler_add_process(uint32_t pid)
{
    /* Add process to the PID matching system */
    int int_pid = (int)pid;
    return exec_set_feature_pids(FEATURE_PROFILE_OFFCPU, &int_pid, 1);
}

int off_cpu_profiler_remove_process(uint32_t pid)
{
    /* Remove process from the PID matching system by setting empty PID list */
    /* Note: This is a simplified implementation. In a complete implementation,
     * we would maintain a list of tracked PIDs and update it properly. */
    ebpf_info("Remove process PID %u from off-CPU profiling\n", pid);
    return 0;  /* Return success for now */
}

void off_cpu_profiler_process_event(void *ctx, void *data, int data_size)
{
    if (!data || data_size < sizeof(struct stack_trace_key_t)) {
        return;
    }

    pthread_mutex_lock(&off_cpu_profiler_mutex);

    if (!g_off_cpu_ctx || !g_off_cpu_ctx->initialized) {
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return;
    }

    struct stack_trace_key_t *event = (struct stack_trace_key_t *)data;

    /* Update statistics */
    update_off_cpu_statistics(g_off_cpu_ctx, event);

    /* Process the event through the standard profiler pipeline */
    if (g_off_cpu_ctx->base.profiler_stop == 0) {
        /* Add to raw stack data for processing */
        int ret = VEC_OK;
        vec_add1(g_off_cpu_ctx->base.raw_stack_data, *event, ret);
        if (ret != VEC_OK) {
            ebpf_warning("Failed to add off-CPU event to raw stack data\n");
            g_off_cpu_ctx->stats.events_dropped++;
        }
    }

    pthread_mutex_unlock(&off_cpu_profiler_mutex);
}

int off_cpu_profiler_export_stats_json(char *buffer, size_t buffer_size)
{
    if (!buffer || buffer_size == 0) {
        return -EINVAL;
    }

    pthread_mutex_lock(&off_cpu_profiler_mutex);

    if (!g_off_cpu_ctx || !g_off_cpu_ctx->initialized) {
        pthread_mutex_unlock(&off_cpu_profiler_mutex);
        return -EINVAL;
    }

    struct off_cpu_profiler_stats *stats = &g_off_cpu_ctx->stats;

    int written = snprintf(buffer, buffer_size,
        "{\n"
        "  \"off_cpu_profiler_stats\": {\n"
        "    \"enabled\": %s,\n"
        "    \"total_block_events\": %lu,\n"
        "    \"total_block_time_ns\": %lu,\n"
        "    \"avg_block_time_ns\": %lu,\n"
        "    \"max_block_time_ns\": %lu,\n"
        "    \"min_block_time_ns\": %lu,\n"
        "    \"pending_events\": %lu,\n"
        "    \"events_dropped\": %lu,\n"
        "    \"stack_trace_failures\": %lu,\n"
        "    \"cache_hits\": %lu,\n"
        "    \"cache_misses\": %lu,\n"
        "    \"cache_hit_rate_percent\": %.2f,\n"
        "    \"events_by_reason\": {\n",
        g_off_cpu_ctx->config.enabled ? "true" : "false",
        stats->total_block_events,
        stats->total_block_time_ns,
        stats->avg_block_time_ns,
        stats->max_block_time_ns,
        stats->min_block_time_ns == UINT64_MAX ? 0 : stats->min_block_time_ns,
        stats->pending_events,
        stats->events_dropped,
        stats->stack_trace_failures,
        stats->cache_hits,
        stats->cache_misses,
        (stats->cache_hits + stats->cache_misses) > 0 ?
            (double)stats->cache_hits / (stats->cache_hits + stats->cache_misses) * 100.0 : 0.0);

    /* Add events by reason */
    for (int i = 0; i < 7 && written < buffer_size; i++) {
        written += snprintf(buffer + written, buffer_size - written,
            "      \"%s\": %lu%s\n",
            off_cpu_block_reason_names[i],
            stats->events_by_reason[i],
            (i < 6) ? "," : "");
    }

    if (written < buffer_size) {
        written += snprintf(buffer + written, buffer_size - written,
            "    },\n"
            "    \"configuration\": {\n"
            "      \"min_block_time_ns\": %lu,\n"
            "      \"max_events\": %u,\n"
            "      \"track_wakers\": %s,\n"
            "      \"classify_block_reasons\": %s\n"
            "    }\n"
            "  }\n"
            "}",
            g_off_cpu_ctx->config.min_block_time_ns,
            g_off_cpu_ctx->config.max_events,
            g_off_cpu_ctx->config.track_wakers ? "true" : "false",
            g_off_cpu_ctx->config.classify_block_reasons ? "true" : "false");
    }

    pthread_mutex_unlock(&off_cpu_profiler_mutex);

    return (written >= buffer_size) ? -ENOSPC : 0;
}

const char* off_cpu_profiler_get_reason_name(uint32_t reason)
{
    if (reason < sizeof(off_cpu_block_reason_names) / sizeof(off_cpu_block_reason_names[0])) {
        return off_cpu_block_reason_names[reason];
    }
    return "Unknown";
}

void off_cpu_profiler_cleanup(void)
{
    pthread_mutex_lock(&off_cpu_profiler_mutex);

    if (g_off_cpu_ctx) {
        if (g_off_cpu_ctx->initialized) {
            off_cpu_profiler_stop();
        }

        clib_mem_free(g_off_cpu_ctx);
        g_off_cpu_ctx = NULL;
    }

    pthread_mutex_unlock(&off_cpu_profiler_mutex);

    ebpf_info("Off-CPU profiler cleaned up\n");
}

/* Internal helper functions */

static int setup_off_cpu_maps(struct bpf_tracer *tracer)
{
    /* Set initial configuration in eBPF maps */
    if (!bpf_table_set_value(tracer, "off_cpu_state_map", MINBLOCK_TIME_IDX,
                             &g_off_cpu_ctx->config.min_block_time_ns)) {
        ebpf_warning("Failed to set minimum block time in eBPF\n");
        return -EIO;
    }

    uint64_t enable_flag = g_off_cpu_ctx->config.enabled ? 1 : 0;
    if (!bpf_table_set_value(tracer, "off_cpu_state_map", ENABLE_IDX, &enable_flag)) {
        ebpf_warning("Failed to set enable flag in eBPF\n");
        return -EIO;
    }

    return 0;
}

static int setup_off_cpu_events(struct bpf_tracer *tracer)
{
    /* Setup perf event output for off-CPU events */
    struct bpf_perf_reader *reader = create_perf_buffer_reader(tracer, "off_cpu_events",
                                                             off_cpu_profiler_process_event,
                                                             NULL, 4, 1, 1000);
    if (!reader) {
        ebpf_warning("Failed to create off-CPU events reader\n");
        return -EIO;
    }

    /* Reader starts automatically when created */
    ebpf_info("Off-CPU events reader created successfully\n");

    return 0;
}

static void update_off_cpu_statistics(struct off_cpu_profiler_context *ctx,
                                     const struct stack_trace_key_t *event)
{
    struct off_cpu_profiler_stats *stats = &ctx->stats;

    stats->total_block_events++;
    stats->total_block_time_ns += event->off_cpu.duration_ns;

    /* Update min/max block times */
    if (event->off_cpu.duration_ns > stats->max_block_time_ns) {
        stats->max_block_time_ns = event->off_cpu.duration_ns;
    }
    if (event->off_cpu.duration_ns < stats->min_block_time_ns) {
        stats->min_block_time_ns = event->off_cpu.duration_ns;
    }

    /* Update average */
    if (stats->total_block_events > 0) {
        stats->avg_block_time_ns = stats->total_block_time_ns / stats->total_block_events;
    }

    /* Update stack trace statistics */
    if (event->userstack >= 0 || event->kernstack >= 0) {
        stats->cache_hits++;
    } else {
        stats->cache_misses++;
        if (event->userstack == -EEXIST || event->kernstack == -EEXIST) {
            stats->stack_trace_failures++;
        }
    }
}