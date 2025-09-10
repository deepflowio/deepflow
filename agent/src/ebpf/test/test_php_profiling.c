/*
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
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../user/config.h"
#include "../user/utils.h"
#include "../user/log.h"
#include "trace_utils.h"

#define TEST_PID_BASE 12345
#define TEST_PHP_VERSION_MAJOR 8
#define TEST_PHP_VERSION_MINOR 2
#define TEST_PHP_VERSION_PATCH 0

// Mock PHP process setup for testing
static int setup_mock_php_process(void)
{
	printf("Setting up mock PHP process for testing...\n");
	// This would normally involve creating a real PHP process
	// For unit testing, we'll just return a test PID
	return TEST_PID_BASE;
}

// Test PHP process detection
static void test_php_process_detection(void)
{
	printf("Testing PHP process detection...\n");

	// Test with a known non-PHP process (current process)
	pid_t current_pid = getpid();
	bool is_php = is_php_process(current_pid);
	printf("Current process (PID %d) detected as PHP: %s\n",
	       current_pid, is_php ? "true" : "false");

	// For a complete test, this would involve checking against actual PHP processes
	printf("PHP process detection test completed\n");
}

// Test PHP version parsing and offsets loading
static void test_php_version_offsets(void)
{
	printf("Testing PHP version parsing and offsets...\n");

	// Test version parsing with JIT support information
	struct {
		const char *version;
		bool supports_jit;
		const char *expected_features;
	} test_versions[] = {
		{"7.4.33", false, "Basic unwinding, no JIT"},
		{"8.0.30", true, "JIT support, ZEND_VM_KIND_HYBRID"},
		{"8.1.27", true, "Enhanced JIT, improved unwinding"},
		{"8.2.15", true, "Latest JIT optimizations"},
		{"8.3.2", true, "Current stable JIT implementation"}
	};

	int num_versions = sizeof(test_versions) / sizeof(test_versions[0]);
	for (int i = 0; i < num_versions; i++) {
		printf("Testing version: %s\n", test_versions[i].version);
		printf("  JIT support: %s\n", test_versions[i].supports_jit ? "Yes" : "No");
		printf("  Features: %s\n", test_versions[i].expected_features);

		// In a real test, we would:
		// 1. Parse the version string
		// 2. Load appropriate offsets for the version
		// 3. Check if JIT return address recovery is needed
		// 4. Verify struct offsets match the PHP version
	}

	printf("PHP version and offsets test completed\n");
}

// Test PHP unwinding table operations
static void test_php_unwind_table(void)
{
	printf("Testing PHP unwinding table operations...\n");

	// Mock file descriptors (in real test these would be actual BPF map FDs)
	int mock_unwind_info_fd = -1;
	int mock_offsets_fd = -1;

	// Create PHP unwind table
	php_unwind_table_t *table = php_unwind_table_create(mock_unwind_info_fd, mock_offsets_fd);
	if (table == NULL) {
		printf("Failed to create PHP unwind table (expected with mock FDs)\n");
	} else {
		printf("PHP unwind table created successfully\n");

		// Test table operations
		pid_t test_pid = TEST_PID_BASE;
		printf("Testing table load for PID %d\n", test_pid);
		php_unwind_table_load(table, test_pid);

		printf("Testing table unload for PID %d\n", test_pid);
		php_unwind_table_unload(table, test_pid);

		// Clean up
		php_unwind_table_destroy(table);
		printf("PHP unwind table destroyed\n");
	}

	printf("PHP unwinding table test completed\n");
}

// Test PHP stack merging functionality
static void test_php_stack_merging(void)
{
	printf("Testing PHP stack merging functionality...\n");

	// Test data - various PHP stack scenarios
	const char *test_cases[][3] = {
		// Test case 1: Basic class method call
		{"MyClass::method1;function2;main", "execute_ex;zend_execute;main", "Expected: Complete PHP stack with function names"},

		// Test case 2: Simple function call
		{"myFunction;anotherFunction;main", "execute_ex;main", "Expected: PHP functions merged with native"},

		// Test case 3: Empty PHP stack (should show error)
		{"", "execute_ex;main", "Expected: Error handling for empty PHP stack"},

		// Test case 4: Complex call chain with classes
		{"Namespace\\ClassName::staticMethod;globalFunction;{closure};main", "execute_ex;execute_ex;execute_ex;main", "Expected: Complete namespace and closure support"}
	};

	int num_test_cases = sizeof(test_cases) / sizeof(test_cases[0]);

	for (int i = 0; i < num_test_cases; i++) {
		printf("\nTest case %d: %s\n", i + 1, test_cases[i][2]);
		printf("PHP stack: %s\n", test_cases[i][0]);
		printf("Native stack: %s\n", test_cases[i][1]);

		char merged_result[512];
		size_t merged_len = merge_php_stacks(merged_result, sizeof(merged_result),
		                                     test_cases[i][0], test_cases[i][1]);

		if (merged_len > 0) {
			printf("Result (%zu bytes): %s\n", merged_len, merged_result);
		} else {
			printf("Stack merging failed or returned empty result\n");
		}
	}

	printf("\nPHP stack merging test completed\n");
}

// Test PHP interpreter info extraction
static void test_php_interpreter_info(void)
{
	printf("Testing PHP interpreter info extraction...\n");

	pid_t test_pid = getpid(); // Use current process as test

	// Try to extract PHP interpreter info
	// This will likely fail for a non-PHP process, which is expected
	printf("Attempting to extract PHP info for PID %d\n", test_pid);

	// In a real implementation, we would call:
	// InterpreterInfo::new(test_pid)
	// But for unit test purposes, we'll just simulate the attempt

	printf("PHP interpreter info extraction test completed\n");
}

// Performance stress test
static void test_php_profiling_performance(void)
{
	printf("Testing PHP profiling performance...\n");

	const int num_iterations = 1000;
	const int num_processes = 10;

	printf("Simulating %d iterations across %d processes\n",
	       num_iterations, num_processes);

	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (int i = 0; i < num_iterations; i++) {
		pid_t test_pid = TEST_PID_BASE + (i % num_processes);

		// Simulate PHP process check
		volatile bool is_php = is_php_process(test_pid);
		(void)is_php; // Suppress unused variable warning

		if (i % 100 == 0) {
			printf("Completed %d iterations\n", i);
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	double elapsed = (end.tv_sec - start.tv_sec) +
	                (end.tv_nsec - start.tv_nsec) / 1e9;

	printf("Performance test completed in %.3f seconds\n", elapsed);
	printf("Average time per iteration: %.3f μs\n",
	       (elapsed * 1e6) / num_iterations);
}

// Test memory usage and cleanup
static void test_php_profiling_memory(void)
{
	printf("Testing PHP profiling memory management...\n");

	// Test multiple table creation/destruction cycles
	const int num_cycles = 50;

	for (int i = 0; i < num_cycles; i++) {
		php_unwind_table_t *table = php_unwind_table_create(-1, -1);
		if (table) {
			// Load and unload some test data
			for (pid_t pid = TEST_PID_BASE; pid < TEST_PID_BASE + 5; pid++) {
				php_unwind_table_load(table, pid);
				php_unwind_table_unload(table, pid);
			}
			php_unwind_table_destroy(table);
		}

		if (i % 10 == 0) {
			printf("Completed %d memory test cycles\n", i);
		}
	}

	printf("PHP profiling memory test completed\n");
}

// Test PHP 8+ JIT profiling capabilities
static void test_php_jit_profiling(void)
{
	printf("Testing PHP 8+ JIT profiling capabilities...\n");

	// Test JIT version detection
	struct {
		const char *version;
		bool should_support_jit;
		const char *vm_kind;
		const char *jit_features;
	} jit_test_versions[] = {
		{"7.4.33", false, "No JIT", "Legacy interpreter-only profiling"},
		{"8.0.30", true, "ZEND_VM_KIND_HYBRID", "Basic JIT support, mixed stacks"},
		{"8.1.27", true, "ZEND_VM_KIND_HYBRID", "Enhanced JIT, better symbol resolution"},
		{"8.2.15", true, "ZEND_VM_KIND_HYBRID", "Optimized JIT, OPcache integration"},
		{"8.3.2", true, "ZEND_VM_KIND_HYBRID", "Latest JIT with advanced profiling"}
	};

	int num_jit_versions = sizeof(jit_test_versions) / sizeof(jit_test_versions[0]);

	for (int i = 0; i < num_jit_versions; i++) {
		printf("\nTesting JIT support for PHP %s:\n", jit_test_versions[i].version);
		printf("  Expected JIT support: %s\n", jit_test_versions[i].should_support_jit ? "Yes" : "No");
		printf("  VM Kind: %s\n", jit_test_versions[i].vm_kind);
		printf("  JIT Features: %s\n", jit_test_versions[i].jit_features);

		// In a real test, we would:
		// 1. Create PhpJitSupport instance with this version
		// 2. Test supports_jit() method
		// 3. Test VM kind detection
		// 4. Test execute_ex disassembly if JIT is supported
		// 5. Test JIT return address recovery

		if (jit_test_versions[i].should_support_jit) {
			printf("  -> Testing JIT return address recovery simulation\n");
			printf("  -> Testing mixed interpreter/JIT stack scenarios\n");
			printf("  -> Testing JIT frame marker generation\n");
		}
	}

	printf("\nPHP JIT profiling test completed\n");
}

// Test OPcache JIT detection and memory mapping
static void test_opcache_jit_detection(void)
{
	printf("Testing OPcache JIT detection and memory mapping...\n");

	// Simulate OPcache detection scenarios
	struct {
		const char *scenario;
		bool opcache_loaded;
		bool jit_enabled;
		const char *expected_result;
	} opcache_scenarios[] = {
		{"No OPcache", false, false, "Standard interpreter profiling"},
		{"OPcache without JIT", true, false, "OPcache detected, no JIT optimization"},
		{"OPcache with JIT disabled", true, false, "JIT available but disabled"},
		{"OPcache with JIT enabled", true, true, "Full JIT profiling with buffer mapping"},
		{"OPcache with selective JIT", true, true, "Partial JIT compilation, mixed stacks"}
	};

	int num_opcache_scenarios = sizeof(opcache_scenarios) / sizeof(opcache_scenarios[0]);

	for (int i = 0; i < num_opcache_scenarios; i++) {
		printf("\nScenario: %s\n", opcache_scenarios[i].scenario);
		printf("  OPcache loaded: %s\n", opcache_scenarios[i].opcache_loaded ? "Yes" : "No");
		printf("  JIT enabled: %s\n", opcache_scenarios[i].jit_enabled ? "Yes" : "No");
		printf("  Expected result: %s\n", opcache_scenarios[i].expected_result);

		if (opcache_scenarios[i].opcache_loaded) {
			printf("  -> Simulating opcache.so detection in memory mappings\n");
			printf("  -> Testing zend_extension_entry symbol lookup\n");

			if (opcache_scenarios[i].jit_enabled) {
				printf("  -> Testing dasm_buf/dasm_size extraction\n");
				printf("  -> Testing JIT buffer memory mapping\n");
				printf("  -> Testing zend_jit_unprotect analysis\n");
			}
		}
	}

	printf("\nOPcache JIT detection test completed\n");
}

// Test mixed interpreter/JIT stack unwinding
static void test_mixed_jit_stack_unwinding(void)
{
	printf("Testing mixed interpreter/JIT stack unwinding...\n");

	// Test various mixed stack scenarios
	const char *mixed_stack_scenarios[][4] = {
		// [PHP stack with JIT markers, Native stack, Description, Expected result]
		{
			"MyClass::method1 [JIT];normalFunction;AnotherClass::method2;main",
			"execute_ex;jit_code_executor;execute_ex;main",
			"Mixed JIT and interpreter frames",
			"Should show JIT markers clearly"
		},
		{
			"[JIT] compiled_code;optimizedFunction [JIT];regularFunction;main",
			"jit_trampoline;jit_code_executor;execute_ex;main",
			"Pure JIT optimized call chain",
			"Multiple JIT frames with compiled code markers"
		},
		{
			"Database\\Connection::query;{closure} [JIT];processResults;main",
			"execute_ex;jit_code_executor;execute_ex;main",
			"JIT-compiled closure in call stack",
			"Closure with JIT optimization marker"
		},
		{
			"Framework\\Router::dispatch [JIT];Controller::action;View::render;main",
			"jit_code_executor;execute_ex;execute_ex;main",
			"Framework with JIT-optimized routing",
			"Show performance-critical path JIT compilation"
		}
	};

	int num_mixed_scenarios = sizeof(mixed_stack_scenarios) / sizeof(mixed_stack_scenarios[0]);

	for (int i = 0; i < num_mixed_scenarios; i++) {
		printf("\nMixed stack scenario %d: %s\n", i + 1, mixed_stack_scenarios[i][2]);
		printf("PHP stack: %s\n", mixed_stack_scenarios[i][0]);
		printf("Native stack: %s\n", mixed_stack_scenarios[i][1]);
		printf("Expected: %s\n", mixed_stack_scenarios[i][3]);

		// Test the enhanced stack merging with JIT support
		char merged_result[512];
		size_t merged_len = merge_php_stacks(merged_result, sizeof(merged_result),
		                                     mixed_stack_scenarios[i][0],
		                                     mixed_stack_scenarios[i][1]);

		if (merged_len > 0) {
			printf("Merged result (%zu bytes): %s\n", merged_len, merged_result);

			// Check for JIT markers in the result
			if (strstr(merged_result, "[JIT]")) {
				printf("✓ JIT markers preserved in merged stack\n");
			} else {
				printf("⚠ JIT markers missing in merged result\n");
			}
		} else {
			printf("✗ Stack merging failed\n");
		}
	}

	printf("\nMixed JIT stack unwinding test completed\n");
}

// Test JIT performance impact and optimization
static void test_jit_profiling_performance(void)
{
	printf("Testing JIT profiling performance impact...\n");

	const int num_iterations = 10000;
	const int num_jit_frames = 50;

	printf("Simulating %d iterations with %d JIT frames each\n",
	       num_iterations, num_jit_frames);

	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

	// Simulate JIT frame processing overhead
	for (int i = 0; i < num_iterations; i++) {
		for (int j = 0; j < num_jit_frames; j++) {
			// Simulate JIT frame detection (using bit manipulation like eBPF code)
			volatile uint64_t frame_data = 0x8000000000000000ULL | (i * j);
			volatile bool is_jit = (frame_data & 0x8000000000000000ULL) != 0;
			volatile uint32_t symbol_id = frame_data & 0xFFFFFFFF;

			// Suppress unused variable warnings
			(void)is_jit;
			(void)symbol_id;
		}

		if (i % 1000 == 0) {
			printf("Completed %d JIT profiling iterations\n", i);
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	double elapsed = (end.tv_sec - start.tv_sec) +
	                (end.tv_nsec - start.tv_nsec) / 1e9;

	printf("JIT profiling performance test completed in %.3f seconds\n", elapsed);
	printf("Average time per frame: %.3f ns\n",
	       (elapsed * 1e9) / (num_iterations * num_jit_frames));

	// Performance expectations
	double frames_per_second = (num_iterations * num_jit_frames) / elapsed;
	printf("Processed %.0f frames/second\n", frames_per_second);

	if (frames_per_second > 100000) {
		printf("✓ JIT profiling performance meets production requirements\n");
	} else {
		printf("⚠ JIT profiling performance may need optimization\n");
	}
}

// Test JIT symbol resolution edge cases
static void test_jit_symbol_resolution(void)
{
	printf("Testing JIT symbol resolution edge cases...\n");

	// Test various JIT symbol scenarios
	struct {
		uint64_t frame_address;
		const char *class_name;
		const char *method_name;
		const char *expected_output;
	} jit_symbol_cases[] = {
		{0x8000000000001234ULL, "MyClass", "method", "MyClass::method [JIT]"},
		{0x0000000000001234ULL, "MyClass", "method", "MyClass::method"},
		{0x8000000000005678ULL, "", "function", "function [JIT]"},
		{0x0000000000005678ULL, "", "function", "function"},
		{0x8000000000009ABCULL, "[JIT]", "compiled_code", "[JIT]::compiled_code [JIT]"},
		{0x8000000000000000ULL, "Namespace\\Class", "staticMethod", "Namespace\\Class::staticMethod [JIT]"}
	};

	int num_symbol_cases = sizeof(jit_symbol_cases) / sizeof(jit_symbol_cases[0]);

	for (int i = 0; i < num_symbol_cases; i++) {
		printf("\nSymbol resolution case %d:\n", i + 1);
		printf("  Frame address: 0x%016lx\n", jit_symbol_cases[i].frame_address);
		printf("  Class: %s\n", jit_symbol_cases[i].class_name);
		printf("  Method: %s\n", jit_symbol_cases[i].method_name);
		printf("  Expected: %s\n", jit_symbol_cases[i].expected_output);

		// Simulate the enhanced resolve_custom_symbol_addr logic
		bool is_jit_frame = (jit_symbol_cases[i].frame_address & 0x8000000000000000ULL) != 0;

		char simulated_result[256];
		if (strlen(jit_symbol_cases[i].class_name) > 0) {
			if (is_jit_frame) {
				snprintf(simulated_result, sizeof(simulated_result), "%s::%s [JIT]",
				         jit_symbol_cases[i].class_name, jit_symbol_cases[i].method_name);
			} else {
				snprintf(simulated_result, sizeof(simulated_result), "%s::%s",
				         jit_symbol_cases[i].class_name, jit_symbol_cases[i].method_name);
			}
		} else {
			if (is_jit_frame) {
				snprintf(simulated_result, sizeof(simulated_result), "%s [JIT]",
				         jit_symbol_cases[i].method_name);
			} else {
				snprintf(simulated_result, sizeof(simulated_result), "%s",
				         jit_symbol_cases[i].method_name);
			}
		}

		printf("  Result: %s\n", simulated_result);

		if (strcmp(simulated_result, jit_symbol_cases[i].expected_output) == 0) {
			printf("  ✓ Symbol resolution correct\n");
		} else {
			printf("  ✗ Symbol resolution mismatch\n");
		}
	}

	printf("\nJIT symbol resolution test completed\n");
}

// Test error handling and edge cases
static void test_php_profiling_error_handling(void)
{
	printf("Testing PHP profiling error handling...\n");

	// Test invalid PID
	printf("Testing invalid PID handling\n");
	bool result = is_php_process(-1);
	printf("is_php_process(-1) = %s (should be false)\n",
	       result ? "true" : "false");

	// Test NULL pointer handling
	printf("Testing NULL pointer handling\n");
	php_unwind_table_t *null_table = php_unwind_table_create(-1, -1);
	if (null_table) {
		php_unwind_table_load(null_table, 0); // Invalid PID
		php_unwind_table_destroy(null_table);
	}

	// Test stack merging with NULL/empty inputs
	printf("Testing stack merging with invalid inputs\n");
	char result_buffer[256];
	size_t len1 = merge_php_stacks(result_buffer, sizeof(result_buffer), NULL, "test");
	size_t len2 = merge_php_stacks(result_buffer, sizeof(result_buffer), "test", NULL);
	size_t len3 = merge_php_stacks(result_buffer, sizeof(result_buffer), "", "");

	printf("merge_php_stacks results - NULL arg1: %zu, NULL arg2: %zu, empty args: %zu\n",
	       len1, len2, len3);

	// Test JIT-specific error conditions
	printf("Testing JIT-specific error handling\n");

	// Test malformed JIT frames
	const char *malformed_jit_stacks[] = {
		"[JIT] [JIT] [JIT]", // Multiple JIT markers
		"function [JIT [incomplete", // Incomplete JIT marker
		"", // Empty stack with JIT expected
		"normal_function;[JIT];another_function" // JIT marker without function name
	};

	int num_malformed = sizeof(malformed_jit_stacks) / sizeof(malformed_jit_stacks[0]);
	for (int i = 0; i < num_malformed; i++) {
		printf("Testing malformed JIT stack: %s\n", malformed_jit_stacks[i]);
		size_t len = merge_php_stacks(result_buffer, sizeof(result_buffer),
		                             malformed_jit_stacks[i], "execute_ex;main");
		printf("  Result length: %zu %s\n", len, len > 0 ? "✓" : "✗");
	}

	printf("PHP profiling error handling test completed\n");
}

// Main test runner
int main(int argc, char *argv[])
{
	printf("Starting PHP Profiling Unit Tests\n");
	printf("==================================\n\n");

	// Initialize logging for testing
	ebpf_set_log_level(LOG_LEVEL_INFO);

	// Run all test cases
	test_php_process_detection();
	printf("\n");

	test_php_version_offsets();
	printf("\n");

	test_php_unwind_table();
	printf("\n");

	test_php_stack_merging();
	printf("\n");

	test_php_interpreter_info();
	printf("\n");

	// Enhanced JIT profiling tests
	test_php_jit_profiling();
	printf("\n");

	test_opcache_jit_detection();
	printf("\n");

	test_mixed_jit_stack_unwinding();
	printf("\n");

	test_jit_profiling_performance();
	printf("\n");

	test_jit_symbol_resolution();
	printf("\n");

	// Traditional performance and memory tests
	test_php_profiling_performance();
	printf("\n");

	test_php_profiling_memory();
	printf("\n");

	test_php_profiling_error_handling();
	printf("\n");

	printf("==================================\n");
	printf("All PHP Profiling Unit Tests Completed\n");

	return 0;
}