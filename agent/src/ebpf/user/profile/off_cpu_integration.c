/*
 * Off-CPU Profiler Integration with Main Profiler System
 * Copyright (c) 2024 Yunshan Networks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "off_cpu_profiler.h" 
#include "profile_common.h"
#include "perf_profiler.h"
#include "../tracer.h"
#include "../log.h"

/* Global off-CPU profiler context for integration */
static struct profiler_context *g_off_cpu_profiler_ctx = NULL;
extern struct profiler_context *g_ctx_array[PROFILER_CTX_NUM];

#define OFFCPU_PROFILER_CTX_IDX 1  // Use index 1 for off-CPU profiler

/**
 * Initialize off-CPU profiler integration with the main profiler system
 */
int off_cpu_profiler_integration_init(void)
{
    if (g_off_cpu_profiler_ctx != NULL) {
        ebpf_warning("Off-CPU profiler integration already initialized\n");
        return -1;
    }
    
    /* Allocate off-CPU profiler context */
    g_off_cpu_profiler_ctx = clib_mem_alloc_aligned("off_cpu_profiler_ctx", 
                                                   sizeof(struct profiler_context), 
                                                   0, NULL);
    if (!g_off_cpu_profiler_ctx) {
        ebpf_warning("Failed to allocate off-CPU profiler context\n");
        return -1;
    }
    
    /* Initialize the profiler context for off-CPU */
    int ret = profiler_context_init(g_off_cpu_profiler_ctx,
                                   "Off-CPU Profiler",
                                   "[OFF-CPU] ",
                                   PROFILER_TYPE_OFFCPU,
                                   true,  // Enable by default
                                   "off_cpu_state_map",
                                   "off_cpu_stack_map_a",
                                   "off_cpu_stack_map_b", 
                                   "off_cpu_custom_stack_map_a",
                                   "off_cpu_custom_stack_map_b",
                                   false, // Process all events, not just matched
                                   true,  // Use delta time for blocking duration
                                   0,     // Sample all events
                                   NULL); // No callback context for now
    
    if (ret != 0) {
        ebpf_warning("Failed to initialize off-CPU profiler context: %d\n", ret);
        clib_mem_free(g_off_cpu_profiler_ctx);
        g_off_cpu_profiler_ctx = NULL;
        return ret;
    }
    
    /* Set CPU aggregation flag for off-CPU profiling */
    g_off_cpu_profiler_ctx->cpu_aggregation_flag = 1;
    
    /* Register in global context array */
    g_ctx_array[OFFCPU_PROFILER_CTX_IDX] = g_off_cpu_profiler_ctx;
    
    /* Initialize the off-CPU profiler subsystem */
    struct off_cpu_profiler_config config = {
        .enabled = true,
        .min_block_time_ns = 50000,  // 50μs
        .max_events = 65536,
        .sample_period = 0,          // All events
        .track_wakers = true,
        .classify_block_reasons = true,
        .enable_stack_traces = true,
        .max_stack_depth = 64
    };
    
    ret = off_cpu_profiler_init(&config, g_off_cpu_profiler_ctx);
    if (ret != 0) {
        ebpf_warning("Failed to initialize off-CPU profiler subsystem: %d\n", ret);
        g_ctx_array[OFFCPU_PROFILER_CTX_IDX] = NULL;
        clib_mem_free(g_off_cpu_profiler_ctx);
        g_off_cpu_profiler_ctx = NULL;
        return ret;
    }
    
    ebpf_info("Off-CPU profiler integration initialized successfully\n");
    return 0;
}

/**
 * Start off-CPU profiler integration
 */
int off_cpu_profiler_integration_start(struct bpf_tracer *tracer)
{
    if (!g_off_cpu_profiler_ctx) {
        ebpf_warning("Off-CPU profiler integration not initialized\n");
        return -1;
    }
    
    /* Enable the eBPF program */
    set_bpf_run_enabled(tracer, g_off_cpu_profiler_ctx, 1);
    
    /* Start the off-CPU profiler */
    int ret = off_cpu_profiler_start();
    if (ret != 0) {
        ebpf_warning("Failed to start off-CPU profiler: %d\n", ret);
        return ret;
    }
    
    ebpf_info("Off-CPU profiler integration started\n");
    return 0;
}

/**
 * Stop off-CPU profiler integration
 */
int off_cpu_profiler_integration_stop(struct bpf_tracer *tracer)
{
    if (!g_off_cpu_profiler_ctx) {
        return 0; // Already stopped or not initialized
    }
    
    /* Disable the eBPF program */
    set_bpf_run_enabled(tracer, g_off_cpu_profiler_ctx, 0);
    
    /* Stop the off-CPU profiler */
    off_cpu_profiler_stop();
    
    ebpf_info("Off-CPU profiler integration stopped\n");
    return 0;
}

/**
 * Process off-CPU stack traces (integration with main profiler pipeline)
 */
void off_cpu_profiler_integration_process(struct bpf_tracer *tracer)
{
    if (!g_off_cpu_profiler_ctx || g_off_cpu_profiler_ctx->profiler_stop == 1) {
        return;
    }
    
    /* Process stack traces using the common profiler infrastructure */
    process_bpf_stacktraces(g_off_cpu_profiler_ctx, tracer);
}

/**
 * Get off-CPU profiler context
 */
struct profiler_context* off_cpu_profiler_integration_get_context(void)
{
    return g_off_cpu_profiler_ctx;
}

/**
 * Cleanup off-CPU profiler integration
 */
void off_cpu_profiler_integration_cleanup(void)
{
    if (g_off_cpu_profiler_ctx) {
        /* Remove from global array */
        g_ctx_array[OFFCPU_PROFILER_CTX_IDX] = NULL;
        
        /* Cleanup the off-CPU profiler */
        off_cpu_profiler_cleanup();
        
        /* Free the context */
        clib_mem_free(g_off_cpu_profiler_ctx);
        g_off_cpu_profiler_ctx = NULL;
        
        ebpf_info("Off-CPU profiler integration cleaned up\n");
    }
}

/**
 * Check if off-CPU profiler is running
 */
bool off_cpu_profiler_integration_is_running(void)
{
    return (g_off_cpu_profiler_ctx && 
            g_off_cpu_profiler_ctx->enable_bpf_profile == 1);
}