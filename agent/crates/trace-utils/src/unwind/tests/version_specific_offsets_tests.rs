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

//! Tests for version-specific offset core types and conversions

use super::setup_test_env;
use super::test_utils::*;
use crate::unwind::version_specific_offsets::*;
use std::collections::HashMap;

#[test]
fn test_php_version_creation_and_display() {
    setup_test_env();

    let version = PHPVersion::new(8, 2, 5);
    assert_eq!(version.major, 8);
    assert_eq!(version.minor, 2);
    assert_eq!(version.patch, 5);
    assert_eq!(version.to_string(), "8.2.5");

    let version_mm = PHPVersion::from_major_minor(8, 1);
    assert_eq!(version_mm.major, 8);
    assert_eq!(version_mm.minor, 1);
    assert_eq!(version_mm.patch, 0);
    assert_eq!(version_mm.to_string(), "8.1.0");
}

#[test]
fn test_php_version_equality_and_hashing() {
    setup_test_env();

    let v1 = PHPVersion::new(8, 1, 0);
    let v2 = PHPVersion::from_major_minor(8, 1);
    let v3 = PHPVersion::new(8, 2, 0);

    assert_eq!(v1, v2);
    assert_ne!(v1, v3);

    // Test HashMap usage
    let mut map = HashMap::new();
    map.insert(v1, "php81");
    assert!(map.contains_key(&v2));
    assert!(!map.contains_key(&v3));
}

#[test]
fn test_nodejs_version_creation_and_display() {
    setup_test_env();

    let version = NodeJSVersion::new(20, 10, 0);
    assert_eq!(version.major, 20);
    assert_eq!(version.minor, 10);
    assert_eq!(version.patch, 0);
    assert_eq!(version.to_string(), "20.10.0");

    let version_mm = NodeJSVersion::from_major_minor(18, 17);
    assert_eq!(version_mm.major, 18);
    assert_eq!(version_mm.minor, 17);
    assert_eq!(version_mm.patch, 0);
}

#[test]
fn test_v8_version_creation_and_display() {
    setup_test_env();

    let version = V8Version::new(11, 8, 0);
    assert_eq!(version.major, 11);
    assert_eq!(version.minor, 8);
    assert_eq!(version.patch, 0);
    assert_eq!(version.to_string(), "11.8.0");
}

#[test]
fn test_nodejs_to_v8_version_mapping() {
    setup_test_env();

    // Test Node.js 16 series -> V8 9.x
    let node16_0 = NodeJSVersion::new(16, 0, 0);
    assert_eq!(node16_0.to_v8_version(), V8Version::new(9, 0, 0));

    let node16_6 = NodeJSVersion::new(16, 6, 0);
    assert_eq!(node16_6.to_v8_version(), V8Version::new(9, 1, 0));

    let node16_15 = NodeJSVersion::new(16, 15, 0);
    assert_eq!(node16_15.to_v8_version(), V8Version::new(9, 4, 0));

    // Test Node.js 18 series -> V8 10.x
    let node18_2 = NodeJSVersion::new(18, 2, 0);
    assert_eq!(node18_2.to_v8_version(), V8Version::new(10, 1, 0));

    let node18_7 = NodeJSVersion::new(18, 7, 0);
    assert_eq!(node18_7.to_v8_version(), V8Version::new(10, 2, 0));

    let node18_17 = NodeJSVersion::new(18, 17, 0);
    assert_eq!(node18_17.to_v8_version(), V8Version::new(10, 8, 0));

    // Test Node.js 20 series -> V8 11.x
    let node20_2 = NodeJSVersion::new(20, 2, 0);
    assert_eq!(node20_2.to_v8_version(), V8Version::new(11, 3, 0));

    let node20_8 = NodeJSVersion::new(20, 8, 0);
    assert_eq!(node20_8.to_v8_version(), V8Version::new(11, 5, 0));

    let node20_12 = NodeJSVersion::new(20, 12, 0);
    assert_eq!(node20_12.to_v8_version(), V8Version::new(11, 8, 0));

    // Test Node.js 21 series -> V8 11.x
    let node21_3 = NodeJSVersion::new(21, 3, 0);
    assert_eq!(node21_3.to_v8_version(), V8Version::new(11, 8, 0));

    let node21_7 = NodeJSVersion::new(21, 7, 0);
    assert_eq!(node21_7.to_v8_version(), V8Version::new(11, 9, 0));

    // Test Node.js 22 series -> V8 12.x
    let node22_0 = NodeJSVersion::new(22, 0, 0);
    assert_eq!(node22_0.to_v8_version(), V8Version::new(12, 4, 0));
}

#[test]
fn test_nodejs_to_v8_version_fallbacks() {
    setup_test_env();

    // Test fallback for future versions
    let node23_0 = NodeJSVersion::new(23, 0, 0);
    assert_eq!(node23_0.to_v8_version(), V8Version::new(12, 4, 0));

    let node25_5 = NodeJSVersion::new(25, 5, 0);
    assert_eq!(node25_5.to_v8_version(), V8Version::new(12, 4, 0));

    // Test fallback for old versions
    let node14_0 = NodeJSVersion::new(14, 0, 0);
    assert_eq!(node14_0.to_v8_version(), V8Version::new(9, 0, 0));
}

#[test]
fn test_version_offset_error_types() {
    setup_test_env();

    let php_version = PHPVersion::new(9, 0, 0); // Unsupported
    let v8_version = V8Version::new(13, 0, 0); // Unsupported
    let node_version = NodeJSVersion::new(25, 0, 0);

    let error1 = VersionOffsetError::UnsupportedPHPVersion(php_version);
    assert!(error1.to_string().contains("Unsupported PHP version"));

    let error2 = VersionOffsetError::UnsupportedV8Version(v8_version);
    assert!(error2.to_string().contains("Unsupported V8 version"));

    let error3 = VersionOffsetError::UnsupportedNodeJSVersion(node_version);
    assert!(error3.to_string().contains("Unsupported Node.js version"));

    let error4 = VersionOffsetError::VersionDetectionFailed(12345);
    assert!(error4
        .to_string()
        .contains("Failed to detect runtime version for process 12345"));

    let error5 = VersionOffsetError::InvalidOffsetValidation(12345, "test error".to_string());
    assert!(error5
        .to_string()
        .contains("Invalid offset validation for process 12345: test error"));

    let error6 = VersionOffsetError::MemoryAccessError("access denied".to_string());
    assert!(error6
        .to_string()
        .contains("Memory access error: access denied"));
}

#[test]
fn test_runtime_info_structures() {
    setup_test_env();

    // Create sample offsets
    let php_offsets = PHPOffsets {
        executor_globals: ExecutorGlobalsOffsets {
            current_execute_data: 0,
            symbol_table: 8,
            function_table: 16,
            class_table: 72,
            vm_stack: 128,
            vm_stack_top: 136,
            vm_stack_end: 144,
            error_reporting: 152,
            bailout: 160,
            exit_status: 168,
        },
        execute_data: ExecuteDataOffsets {
            opline: 0,
            call: 8,
            return_value: 16,
            func: 24,
            this: 32,
            prev_execute_data: 48,
            symbol_table: 56,
            run_time_cache: 64,
        },
        zend_function: ZendFunctionOffsets {
            type_: 0,
            arg_flags: 8,
            fn_flags: 16,
            function_name: 24,
            scope: 32,
            prototype: 40,
            num_args: 48,
            required_num_args: 52,
        },
        zend_string: ZendStringOffsets {
            gc: 0,
            h: 16,
            len: 24,
            val: 32,
        },
    };

    let php_version = PHPVersion::new(8, 1, 0);
    // Test that we can create the runtime info structure (using leaked Box for static lifetime)
    let php_offsets_static: &'static PHPOffsets = Box::leak(Box::new(php_offsets));
    let php_runtime_info = PHPRuntimeInfo {
        version: php_version,
        executor_globals_address: 0x7f8b40000000,
        offsets: php_offsets_static,
    };

    assert_eq!(php_runtime_info.version, php_version);
    assert_eq!(php_runtime_info.executor_globals_address, 0x7f8b40000000);
    assert!(validate_php_offsets(php_runtime_info.offsets));

    // Create V8 runtime info
    let v8_offsets = V8Offsets {
        isolate: IsolateOffsets {
            heap: 8,
            thread_local_top: 32,
            context: 64,
            pending_exception: 72,
            scheduled_exception: 80,
            external_caught_exception: 88,
            try_catch_handler: 96,
        },
        thread_local_top: ThreadLocalTopOffsets {
            js_entry_sp: 0,
            c_entry_fp: 8,
            handler: 16,
            current_context: 24,
            pending_exception: 32,
            rethrowing_message: 40,
            thread_id: 48,
        },
        js_frame: JSFrameOffsets {
            fp: 0,
            sp: 8,
            pc: 16,
            constant_pool: 24,
            context: 32,
            function: 40,
        },
        js_function: JSFunctionOffsets {
            shared_function_info: 16,
            code: 24,
            context: 32,
            feedback_cell: 40,
        },
        shared_function_info: SharedFunctionInfoOffsets {
            name_or_scope_info: 16,
            script: 24,
            start_position: 32,
            end_position: 36,
            function_literal_id: 40,
        },
    };

    let node_version = NodeJSVersion::new(20, 10, 0);
    let v8_version = node_version.to_v8_version();
    let v8_offsets_static: &'static V8Offsets = Box::leak(Box::new(v8_offsets));
    let nodejs_runtime_info = NodeJSRuntimeInfo {
        node_version,
        v8_version,
        isolate_address: 0x7f8b50000000,
        offsets: v8_offsets_static,
    };

    assert_eq!(nodejs_runtime_info.node_version, node_version);
    assert_eq!(nodejs_runtime_info.v8_version, v8_version);
    assert_eq!(nodejs_runtime_info.isolate_address, 0x7f8b50000000);
    assert!(validate_v8_offsets(nodejs_runtime_info.offsets));
}

#[test]
fn test_all_version_combinations() {
    setup_test_env();

    // Test comprehensive Node.js to V8 version mapping
    let test_cases = vec![
        // (node_major, node_minor, expected_v8_major, expected_v8_minor)
        (16, 0, 9, 0),
        (16, 3, 9, 0),
        (16, 4, 9, 0),
        (16, 5, 9, 1),
        (16, 7, 9, 1),
        (16, 9, 9, 1),
        (16, 10, 9, 4),
        (16, 12, 9, 4),
        (16, 15, 9, 4),
        (16, 20, 9, 4),
        (18, 0, 10, 1),
        (18, 2, 10, 1),
        (18, 4, 10, 1),
        (18, 5, 10, 2),
        (18, 7, 10, 2),
        (18, 9, 10, 2),
        (18, 10, 10, 7),
        (18, 12, 10, 7),
        (18, 15, 10, 7),
        (18, 16, 10, 8),
        (18, 18, 10, 8),
        (18, 19, 10, 8),
        (18, 25, 10, 8),
        (20, 0, 11, 3),
        (20, 2, 11, 3),
        (20, 4, 11, 3),
        (20, 5, 11, 5),
        (20, 7, 11, 5),
        (20, 9, 11, 5),
        (20, 10, 11, 8),
        (20, 12, 11, 8),
        (20, 15, 11, 8),
        (20, 20, 11, 8),
        (21, 0, 11, 8),
        (21, 2, 11, 8),
        (21, 4, 11, 8),
        (21, 5, 11, 9),
        (21, 7, 11, 9),
        (21, 9, 11, 9),
        (21, 15, 11, 9),
        (22, 0, 12, 4),
        (22, 5, 12, 4),
        (22, 10, 12, 4),
    ];

    for (node_major, node_minor, expected_v8_major, expected_v8_minor) in test_cases {
        let node_version = NodeJSVersion::new(node_major, node_minor, 0);
        let v8_version = node_version.to_v8_version();

        assert_eq!(
            v8_version.major, expected_v8_major,
            "Node.js {}.{} should map to V8 {}.x, got {}.{}",
            node_major, node_minor, expected_v8_major, v8_version.major, v8_version.minor
        );
        assert_eq!(
            v8_version.minor,
            expected_v8_minor,
            "Node.js {}.{} should map to V8 {}.{}, got {}.{}",
            node_major,
            node_minor,
            expected_v8_major,
            expected_v8_minor,
            v8_version.major,
            v8_version.minor
        );
    }
}
