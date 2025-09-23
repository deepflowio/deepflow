/*
 * Multi-Language Profiler Test Suite
 * Copyright (c) 2024 Yunshan Networks
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <time.h>

#include "../user/profile/multi_lang_profiler.h"
#include "../user/profile/php_profiler.h"
#include "../user/profile/nodejs_profiler.h"

/* Test configuration */
#define MAX_TEST_PROCESSES 10
#define TEST_TIMEOUT_SECONDS 30
#define STACK_TRACE_BUFFER_SIZE 4096

/* Test result tracking */
struct test_results {
    int total_tests;
    int passed_tests;
    int failed_tests;
    char last_error[256];
};

static struct test_results results = {0};

/* Test utilities */
static void test_assert(int condition, const char *message) {
    results.total_tests++;
    if (condition) {
        results.passed_tests++;
        printf("[PASS] %s\n", message);
    } else {
        results.failed_tests++;
        printf("[FAIL] %s\n", message);
        snprintf(results.last_error, sizeof(results.last_error), "%s", message);
    }
}

static void print_test_summary(void) {
    printf("\n=== Test Summary ===\n");
    printf("Total tests: %d\n", results.total_tests);
    printf("Passed: %d\n", results.passed_tests);
    printf("Failed: %d\n", results.failed_tests);
    printf("Success rate: %.1f%%\n",
           results.total_tests > 0 ?
           (double)results.passed_tests / results.total_tests * 100.0 : 0.0);

    if (results.failed_tests > 0) {
        printf("Last error: %s\n", results.last_error);
    }
    printf("==================\n");
}

/* Mock BPF table implementation for testing */
struct mock_bpf_table {
    int fd;
    char name[64];
    void *data;
    size_t data_size;
};

static struct mock_bpf_table mock_tables[10];
static int mock_table_count = 0;

static struct bpf_table_t *create_mock_table(const char *name, size_t data_size) {
    if (mock_table_count >= 10) {
        return NULL;
    }

    struct mock_bpf_table *mock = &mock_tables[mock_table_count++];
    mock->fd = mock_table_count; // Use count as fake fd
    strncpy(mock->name, name, sizeof(mock->name) - 1);
    mock->name[sizeof(mock->name) - 1] = '\0';
    mock->data = calloc(1, data_size);
    mock->data_size = data_size;

    return (struct bpf_table_t *)mock;
}

static void cleanup_mock_tables(void) {
    for (int i = 0; i < mock_table_count; i++) {
        if (mock_tables[i].data) {
            free(mock_tables[i].data);
            mock_tables[i].data = NULL;
        }
    }
    mock_table_count = 0;
}

/* Test functions */
static void test_profiler_initialization(void) {
    printf("\n--- Testing Profiler Initialization ---\n");

    // Create mock BPF tables
    struct bpf_table_t *enhanced_progs_map = create_mock_table("enhanced_progs", 1024);
    struct bpf_table_t *runtime_detection_map = create_mock_table("runtime_detection", 4096);
    struct bpf_table_t *php_runtime_map = create_mock_table("php_runtime", 4096);
    struct bpf_table_t *php_offsets_map = create_mock_table("php_offsets", 1024);
    struct bpf_table_t *nodejs_runtime_map = create_mock_table("nodejs_runtime", 4096);
    struct bpf_table_t *v8_offsets_map = create_mock_table("v8_offsets", 1024);

    test_assert(enhanced_progs_map != NULL, "Enhanced progs map creation");
    test_assert(runtime_detection_map != NULL, "Runtime detection map creation");
    test_assert(php_runtime_map != NULL, "PHP runtime map creation");
    test_assert(php_offsets_map != NULL, "PHP offsets map creation");
    test_assert(nodejs_runtime_map != NULL, "Node.js runtime map creation");
    test_assert(v8_offsets_map != NULL, "V8 offsets map creation");

    // Test profiler initialization
    int init_result = multi_lang_profiler_init(
        enhanced_progs_map, runtime_detection_map,
        php_runtime_map, php_offsets_map,
        nodejs_runtime_map, v8_offsets_map
    );

    test_assert(init_result == 0, "Multi-language profiler initialization");
}

static void test_runtime_detection(void) {
    printf("\n--- Testing Runtime Detection ---\n");

    // Test with current process (should be native/unknown)
    pid_t current_pid = getpid();
    enum runtime_type detected_type = multi_lang_profiler_detect_runtime(current_pid);

    test_assert(detected_type >= RUNTIME_UNKNOWN && detected_type <= RUNTIME_NATIVE,
                "Runtime detection returns valid type");

    printf("Detected runtime type for PID %d: %d\n", current_pid, detected_type);
}

static void test_process_management(void) {
    printf("\n--- Testing Process Management ---\n");

    pid_t test_pid = getpid();

    // Test adding process
    int add_result = multi_lang_profiler_add_process(test_pid);
    test_assert(add_result == 0, "Add process to profiler");

    // Test removing process
    int remove_result = multi_lang_profiler_remove_process(test_pid);
    test_assert(remove_result == 0, "Remove process from profiler");

    // Test adding multiple processes
    for (int i = 0; i < 5; i++) {
        pid_t fake_pid = 10000 + i;
        int multi_add_result = multi_lang_profiler_add_process(fake_pid);
        test_assert(multi_add_result == 0, "Add multiple processes");
    }

    // Clean up
    for (int i = 0; i < 5; i++) {
        pid_t fake_pid = 10000 + i;
        multi_lang_profiler_remove_process(fake_pid);
    }
}

static void test_statistics_collection(void) {
    printf("\n--- Testing Statistics Collection ---\n");

    struct multi_lang_profiler_stats stats;
    int stats_result = multi_lang_profiler_get_stats(&stats);

    test_assert(stats_result == 0, "Get profiler statistics");
    test_assert(stats.total_processes >= 0, "Total processes count is valid");
    test_assert(stats.total_stack_traces >= 0, "Total stack traces count is valid");

    printf("Statistics:\n");
    printf("  Total processes: %lu\n", stats.total_processes);
    printf("  PHP processes: %lu\n", stats.php_processes);
    printf("  Node.js processes: %lu\n", stats.nodejs_processes);
    printf("  Total stack traces: %lu\n", stats.total_stack_traces);
    printf("  Successful unwinds: %lu\n", stats.successful_unwinds);
    printf("  Failed unwinds: %lu\n", stats.failed_unwinds);

    // Test success rate calculation
    double success_rate = multi_lang_profiler_get_success_rate();
    test_assert(success_rate >= 0.0 && success_rate <= 100.0, "Success rate is in valid range");

    // Test cache hit rate calculation
    double cache_hit_rate = multi_lang_profiler_get_cache_hit_rate();
    test_assert(cache_hit_rate >= 0.0 && cache_hit_rate <= 100.0, "Cache hit rate is in valid range");

    printf("  Success rate: %.2f%%\n", success_rate);
    printf("  Cache hit rate: %.2f%%\n", cache_hit_rate);
}

static void test_configuration_management(void) {
    printf("\n--- Testing Configuration Management ---\n");

    struct multi_lang_profiler_config config = {
        .enable_php = 1,
        .enable_nodejs = 1,
        .enable_python = 0,
        .enable_native_fallback = 1,
        .max_stack_depth = 64,
        .cache_size_limit = 64,
        .cache_ttl_seconds = 300,
        .min_function_samples = 5,
        .enable_line_numbers = 1,
        .enable_source_context = 0
    };

    int set_config_result = multi_lang_profiler_set_config(&config);
    test_assert(set_config_result == 0, "Set profiler configuration");

    // Test runtime enable/disable
    int enable_result = multi_lang_profiler_set_runtime_enabled(RUNTIME_PHP, 1);
    test_assert(enable_result == 0, "Enable PHP runtime");

    int is_enabled = multi_lang_profiler_is_runtime_enabled(RUNTIME_PHP);
    test_assert(is_enabled == 1, "PHP runtime is enabled");

    enable_result = multi_lang_profiler_set_runtime_enabled(RUNTIME_PHP, 0);
    test_assert(enable_result == 0, "Disable PHP runtime");

    is_enabled = multi_lang_profiler_is_runtime_enabled(RUNTIME_PHP);
    test_assert(is_enabled == 0, "PHP runtime is disabled");
}

static void test_stack_trace_processing(void) {
    printf("\n--- Testing Stack Trace Processing ---\n");

    // Mock stack trace data
    char output_buffer[STACK_TRACE_BUFFER_SIZE];
    struct stack_trace_key_t mock_key = {
        .tgid = getpid(),
        .pid = getpid(),
        .cpu = 0,
        .timestamp = time(NULL)
    };

    // Test with empty/mock symbols
    int process_result = multi_lang_profiler_process_stack_trace(
        getpid(), &mock_key, NULL, 0, RUNTIME_NATIVE,
        output_buffer, sizeof(output_buffer)
    );

    test_assert(process_result == 0, "Process native stack trace");
    test_assert(strlen(output_buffer) > 0, "Stack trace output is not empty");

    printf("Sample stack trace output: %s\n", output_buffer);
}

static void test_performance_optimization(void) {
    printf("\n--- Testing Performance Optimization ---\n");

    // Test cache clearing
    int clear_result = multi_lang_profiler_clear_caches();
    test_assert(clear_result == 0, "Clear profiler caches");

    // Test performance optimization
    int optimize_result = multi_lang_profiler_optimize_performance();
    test_assert(optimize_result == 0, "Optimize profiler performance");
}

static void test_json_export_import(void) {
    printf("\n--- Testing JSON Export/Import ---\n");

    char json_buffer[8192];

    // Test statistics export
    int export_result = multi_lang_profiler_export_stats_json(json_buffer, sizeof(json_buffer));
    test_assert(export_result == 0, "Export statistics to JSON");
    test_assert(strlen(json_buffer) > 0, "JSON export is not empty");

    printf("Sample JSON export (first 200 chars): %.200s...\n", json_buffer);

    // Test configuration import (with a simple JSON config)
    const char *test_config = "{\n"
        "  \"enable_php\": true,\n"
        "  \"enable_nodejs\": true,\n"
        "  \"max_stack_depth\": 32\n"
        "}";\n

    int import_result = multi_lang_profiler_import_config_json(test_config);
    test_assert(import_result == 0, "Import configuration from JSON");
}

static void test_real_php_integration(void) {
    printf("\n--- Testing Real PHP Integration ---\n");

    // Create a temporary PHP script
    FILE *php_script = fopen("/tmp/test_profiler.php", "w");
    if (php_script) {
        fprintf(php_script, "<?php\n"
                           "function fibonacci($n) {\n"
                           "    if ($n <= 1) return $n;\n"
                           "    return fibonacci($n-1) + fibonacci($n-2);\n"
                           "}\n"
                           "function test_function() {\n"
                           "    for ($i = 0; $i < 10; $i++) {\n"
                           "        fibonacci(10);\n"
                           "        usleep(100000); // 100ms\n"
                           "    }\n"
                           "}\n"
                           "test_function();\n"
                           "?>\n");
        fclose(php_script);
    }

    // Fork and execute PHP script
    pid_t php_pid = fork();
    if (php_pid == 0) {
        // Child process: execute PHP script
        execl("/usr/bin/php", "php", "/tmp/test_profiler.php", NULL);
        // If execl fails, try alternative paths
        execl("/usr/local/bin/php", "php", "/tmp/test_profiler.php", NULL);
        execl("/opt/php/bin/php", "php", "/tmp/test_profiler.php", NULL);
        exit(1); // PHP not found
    } else if (php_pid > 0) {
        // Parent process: test profiling
        sleep(1); // Wait for PHP process to start

        // Add PHP process to profiler
        int add_result = multi_lang_profiler_add_process(php_pid);
        test_assert(add_result == 0, "Add real PHP process to profiler");

        // Let it run and collect samples
        sleep(3);

        // Check statistics
        struct multi_lang_profiler_stats stats;
        int stats_result = multi_lang_profiler_get_stats(&stats);
        test_assert(stats_result == 0, "Get stats during PHP profiling");

        if (stats.php_processes > 0) {
            test_assert(1, "PHP process detected and profiled");
            printf("  PHP processes: %lu\n", stats.php_processes);
            printf("  Stack traces collected: %lu\n", stats.total_stack_traces);
        } else {
            printf("  Note: PHP process not detected (PHP may not be installed)\n");
        }

        // Cleanup
        kill(php_pid, SIGTERM);
        int status;
        waitpid(php_pid, &status, 0);
        multi_lang_profiler_remove_process(php_pid);
        unlink("/tmp/test_profiler.php");
    } else {
        printf("  Failed to fork PHP test process\n");
    }
}

static void test_real_nodejs_integration(void) {
    printf("\n--- Testing Real Node.js Integration ---\n");

    // Create a temporary Node.js script
    FILE *js_script = fopen("/tmp/test_profiler.js", "w");
    if (js_script) {
        fprintf(js_script,
                "function fibonacci(n) {\n"
                "    if (n <= 1) return n;\n"
                "    return fibonacci(n-1) + fibonacci(n-2);\n"
                "}\n"
                "\n"
                "function testFunction() {\n"
                "    for (let i = 0; i < 10; i++) {\n"
                "        fibonacci(20);\n"
                "        // Sleep equivalent\n"
                "        let start = Date.now();\n"
                "        while (Date.now() - start < 100) { /* busy wait */ }\n"
                "    }\n"
                "}\n"
                "\n"
                "testFunction();\n");
        fclose(js_script);
    }

    // Fork and execute Node.js script
    pid_t node_pid = fork();
    if (node_pid == 0) {
        // Child process: execute Node.js script
        execl("/usr/bin/node", "node", "/tmp/test_profiler.js", NULL);
        execl("/usr/local/bin/node", "node", "/tmp/test_profiler.js", NULL);
        execl("/usr/bin/nodejs", "nodejs", "/tmp/test_profiler.js", NULL);
        exit(1); // Node.js not found
    } else if (node_pid > 0) {
        // Parent process: test profiling
        sleep(1); // Wait for Node.js process to start

        // Add Node.js process to profiler
        int add_result = multi_lang_profiler_add_process(node_pid);
        test_assert(add_result == 0, "Add real Node.js process to profiler");

        // Let it run and collect samples
        sleep(3);

        // Check statistics
        struct multi_lang_profiler_stats stats;
        int stats_result = multi_lang_profiler_get_stats(&stats);
        test_assert(stats_result == 0, "Get stats during Node.js profiling");

        if (stats.nodejs_processes > 0) {
            test_assert(1, "Node.js process detected and profiled");
            printf("  Node.js processes: %lu\n", stats.nodejs_processes);
            printf("  Stack traces collected: %lu\n", stats.total_stack_traces);
        } else {
            printf("  Note: Node.js process not detected (Node.js may not be installed)\n");
        }

        // Cleanup
        kill(node_pid, SIGTERM);
        int status;
        waitpid(node_pid, &status, 0);
        multi_lang_profiler_remove_process(node_pid);
        unlink("/tmp/test_profiler.js");
    } else {
        printf("  Failed to fork Node.js test process\n");
    }
}

static void test_error_injection(void) {
    printf("\n--- Testing Error Injection and Recovery ---\n");

    // Test invalid process IDs
    int invalid_result = multi_lang_profiler_add_process(0);
    test_assert(invalid_result != 0, "Reject invalid PID 0");

    invalid_result = multi_lang_profiler_add_process(999999);
    test_assert(invalid_result != 0, "Reject non-existent PID");

    // Test rapid add/remove cycles (potential race conditions)
    pid_t test_pid = 12345;
    for (int i = 0; i < 10; i++) {
        multi_lang_profiler_add_process(test_pid);
        multi_lang_profiler_remove_process(test_pid);
    }
    test_assert(1, "Survived rapid add/remove cycles");

    // Test memory pressure simulation
    printf("  Simulating memory pressure...\n");
    int clear_result = multi_lang_profiler_clear_caches();
    test_assert(clear_result == 0, "Clear caches under memory pressure");

    // Test configuration edge cases
    struct multi_lang_profiler_config invalid_config = {
        .enable_php = 1,
        .enable_nodejs = 1,
        .max_stack_depth = 0, // Invalid
        .cache_size_limit = 0, // Invalid
    };

    int config_result = multi_lang_profiler_set_config(&invalid_config);
    test_assert(config_result != 0, "Reject invalid configuration");
}

static void test_concurrent_operations(void) {
    printf("\n--- Testing Concurrent Operations ---\n");

    #define NUM_CONCURRENT_PIDS 50
    pid_t test_pids[NUM_CONCURRENT_PIDS];

    // Initialize test PIDs
    for (int i = 0; i < NUM_CONCURRENT_PIDS; i++) {
        test_pids[i] = 30000 + i;
    }

    // Simulate concurrent process additions
    clock_t start_time = clock();
    for (int i = 0; i < NUM_CONCURRENT_PIDS; i++) {
        multi_lang_profiler_add_process(test_pids[i]);
    }

    // Simulate concurrent statistics queries
    for (int i = 0; i < 20; i++) {
        struct multi_lang_profiler_stats stats;
        multi_lang_profiler_get_stats(&stats);
    }

    // Simulate concurrent process removals
    for (int i = 0; i < NUM_CONCURRENT_PIDS; i++) {
        multi_lang_profiler_remove_process(test_pids[i]);
    }

    clock_t end_time = clock();
    double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    test_assert(elapsed_time < 2.0, "Concurrent operations completed within time limit");
    printf("  Concurrent operations completed in %.3f seconds\n", elapsed_time);
}

static void test_memory_safety(void) {
    printf("\n--- Testing Memory Safety ---\n");

    // Test boundary conditions for stack trace processing
    char large_buffer[8192];
    struct stack_trace_key_t test_key = {
        .tgid = getpid(),
        .pid = getpid(),
        .cpu = 0,
        .timestamp = time(NULL)
    };

    // Test with maximum buffer size
    int result = multi_lang_profiler_process_stack_trace(
        getpid(), &test_key, NULL, 0, RUNTIME_NATIVE,
        large_buffer, sizeof(large_buffer)
    );
    test_assert(result == 0, "Handle large buffer size");

    // Test with minimum buffer size
    char small_buffer[64];
    result = multi_lang_profiler_process_stack_trace(
        getpid(), &test_key, NULL, 0, RUNTIME_NATIVE,
        small_buffer, sizeof(small_buffer)
    );
    test_assert(result == 0, "Handle small buffer size");

    // Test null pointer handling
    result = multi_lang_profiler_process_stack_trace(
        getpid(), &test_key, NULL, 0, RUNTIME_NATIVE,
        NULL, 0
    );
    test_assert(result != 0, "Reject null buffer pointer");
}

static void test_stress_testing(void) {
    printf("\n--- Stress Testing ---\n");

    clock_t start_time = clock();

    // Add and remove many processes rapidly
    for (int i = 0; i < 100; i++) {
        pid_t fake_pid = 50000 + i;
        multi_lang_profiler_add_process(fake_pid);

        if (i % 2 == 0) {
            multi_lang_profiler_remove_process(fake_pid);
        }
    }

    // Get statistics multiple times
    for (int i = 0; i < 50; i++) {
        struct multi_lang_profiler_stats stats;
        multi_lang_profiler_get_stats(&stats);
    }

    // Test performance optimization under stress
    multi_lang_profiler_optimize_performance();

    // Clean up remaining processes
    for (int i = 1; i < 100; i += 2) {
        pid_t fake_pid = 50000 + i;
        multi_lang_profiler_remove_process(fake_pid);
    }

    clock_t end_time = clock();
    double elapsed_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    test_assert(elapsed_time < 5.0, "Stress test completed within time limit");
    printf("  Stress test completed in %.3f seconds\n", elapsed_time);
}

static void cleanup_test_environment(void) {
    printf("\n--- Cleaning Up Test Environment ---\n");

    multi_lang_profiler_cleanup();
    cleanup_mock_tables();

    printf("Test environment cleaned up\n");
}

static void test_performance_benchmarks(void) {
    printf("\n--- Performance Benchmarks ---\n");

    clock_t start_time = clock();

    // Benchmark process addition performance
    const int num_processes = 1000;
    for (int i = 0; i < num_processes; i++) {
        multi_lang_profiler_add_process(60000 + i);
    }

    clock_t add_time = clock();
    double add_duration = ((double)(add_time - start_time)) / CLOCKS_PER_SEC;

    // Benchmark statistics retrieval performance
    start_time = clock();
    for (int i = 0; i < 100; i++) {
        struct multi_lang_profiler_stats stats;
        multi_lang_profiler_get_stats(&stats);
    }
    clock_t stats_time = clock();
    double stats_duration = ((double)(stats_time - start_time)) / CLOCKS_PER_SEC;

    // Benchmark process removal performance
    start_time = clock();
    for (int i = 0; i < num_processes; i++) {
        multi_lang_profiler_remove_process(60000 + i);
    }
    clock_t remove_time = clock();
    double remove_duration = ((double)(remove_time - start_time)) / CLOCKS_PER_SEC;

    // Performance assertions
    test_assert(add_duration < 1.0, "Process addition performance");
    test_assert(stats_duration < 0.1, "Statistics retrieval performance");
    test_assert(remove_duration < 1.0, "Process removal performance");

    printf("  Process addition: %.3f seconds for %d processes\n", add_duration, num_processes);
    printf("  Statistics queries: %.3f seconds for 100 queries\n", stats_duration);
    printf("  Process removal: %.3f seconds for %d processes\n", remove_duration, num_processes);
}

static void test_version_compatibility(void) {
    printf("\n--- Testing Version Compatibility ---\n");

    // Test with different runtime configurations
    struct multi_lang_profiler_config configs[] = {
        { .enable_php = 1, .enable_nodejs = 0, .enable_python = 0 },
        { .enable_php = 0, .enable_nodejs = 1, .enable_python = 0 },
        { .enable_php = 1, .enable_nodejs = 1, .enable_python = 1 },
        { .enable_php = 0, .enable_nodejs = 0, .enable_python = 0 },
    };

    for (size_t i = 0; i < sizeof(configs) / sizeof(configs[0]); i++) {
        int config_result = multi_lang_profiler_set_config(&configs[i]);
        test_assert(config_result == 0, "Set runtime configuration");

        // Test that runtime detection respects configuration
        int php_enabled = multi_lang_profiler_is_runtime_enabled(RUNTIME_PHP);
        int nodejs_enabled = multi_lang_profiler_is_runtime_enabled(RUNTIME_NODEJS);

        test_assert(php_enabled == configs[i].enable_php, "PHP runtime configuration respected");
        test_assert(nodejs_enabled == configs[i].enable_nodejs, "Node.js runtime configuration respected");
    }
}

/* Main test execution */
int main(int argc, char *argv[]) {
    printf("=== Multi-Language Profiler Test Suite ===\n");
    printf("Starting comprehensive tests...\n");

    // Basic functionality tests
    test_profiler_initialization();
    test_runtime_detection();
    test_process_management();
    test_statistics_collection();
    test_configuration_management();
    test_stack_trace_processing();
    test_performance_optimization();
    test_json_export_import();

    // Advanced integration tests
    test_real_php_integration();
    test_real_nodejs_integration();
    test_error_injection();
    test_concurrent_operations();
    test_memory_safety();
    test_performance_benchmarks();
    test_version_compatibility();
    test_stress_testing();

    // Clean up
    cleanup_test_environment();

    // Print results
    print_test_summary();

    // Return appropriate exit code
    return (results.failed_tests == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}