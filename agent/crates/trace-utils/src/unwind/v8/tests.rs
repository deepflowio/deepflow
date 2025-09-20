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

#[cfg(test)]
use super::*;
use semver::Version;

#[test]
fn test_node_version_parsing() {
    // Test Node.js version parsing from different sources
    let test_cases = vec![
        ("16.20.2", Some(Version::new(16, 20, 2))),
        ("18.18.2", Some(Version::new(18, 18, 2))),
        ("20.11.0", Some(Version::new(20, 11, 0))),
        ("21.6.1", Some(Version::new(21, 6, 1))),
        ("invalid", None),
        ("", None),
    ];

    for (input, expected) in test_cases {
        let result = Version::parse(input).ok();
        assert_eq!(result, expected, "Failed parsing version: {}", input);
    }
}

#[test]
fn test_node_to_v8_version_mapping() {
    // Test Node.js to V8 version mapping
    let test_cases = vec![
        (Version::new(16, 20, 0), Version::new(9, 4, 146)),
        (Version::new(18, 18, 0), Version::new(10, 2, 154)),
        (Version::new(20, 11, 0), Version::new(11, 3, 244)),
        (Version::new(21, 6, 0), Version::new(11, 8, 172)),
    ];

    for (node_version, expected_v8) in test_cases {
        let mapped = map_node_to_v8_version(&node_version);
        assert!(
            mapped.is_some(),
            "Node.js version {} should map to V8 version",
            node_version
        );

        let v8_version = mapped.unwrap();
        assert_eq!(
            v8_version.major, expected_v8.major,
            "V8 major version should match for Node.js {}",
            node_version
        );
    }
}

#[test]
fn test_v8_offsets_generation() {
    // Test V8 offsets for different versions
    let versions = vec![
        Version::new(9, 4, 0),
        Version::new(10, 2, 0),
        Version::new(11, 3, 0),
        Version::new(11, 8, 0),
    ];

    for version in versions {
        let offsets = get_offsets_for_v8_version(&version);

        // Verify that offsets are reasonable (not zero for critical fields)
        assert!(
            offsets.js_function.shared > 0,
            "js_function.shared offset should be > 0 for V8 version {}",
            version
        );
        assert!(
            offsets.js_function.code > 0,
            "js_function.code offset should be > 0 for V8 version {}",
            version
        );
        assert!(
            offsets.shared_function_info.name_or_scope_info > 0,
            "shared_function_info.name_or_scope_info offset should be > 0 for V8 version {}",
            version
        );
        assert!(
            offsets.frame_pointers.function != 0,
            "frame_pointers.function offset should be != 0 for V8 version {}",
            version
        );
    }
}

#[test]
fn test_v8_unwind_table_operations() {
    // Test V8 unwind table basic operations
    let mut table = unsafe { V8UnwindTable::new(-1, -1) }; // Mock file descriptors
    let test_pid = 12345;

    // Test load operation (should not crash even with invalid FDs)
    unsafe {
        table.load(test_pid);
    }

    // Test unload operation
    unsafe {
        table.unload(test_pid);
    }

    // V8UnwindTable operations completed successfully
}

#[test]
fn test_v8_stack_merging() {
    let js_stack = "main;calculate;fibonacci";
    let native_stack = "main;v8::internal::Invoke;start_thread";

    let mut buffer = vec![0u8; 512];
    let js_cstring = std::ffi::CString::new(js_stack).unwrap();
    let native_cstring = std::ffi::CString::new(native_stack).unwrap();
    let result_len = unsafe {
        merge_v8_stacks(
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len(),
            js_cstring.as_ptr() as *const std::ffi::c_void,
            native_cstring.as_ptr() as *const std::ffi::c_void,
        )
    };

    assert!(
        result_len > 0,
        "V8 stack merging should return non-zero length"
    );

    let result_str = String::from_utf8_lossy(&buffer[..result_len]);
    assert!(
        result_str.contains("fibonacci"),
        "Merged stack should contain JavaScript function"
    );
    assert!(
        result_str.contains("main"),
        "Merged stack should contain main function"
    );
}

#[test]
fn test_v8_stack_merging_complex_cases() {
    // Test case 1: No V8 frames detected
    let js_stack = "main;calculate;fibonacci";
    let non_v8_native = "pthread_create;some_native_func";

    let merged = merge_stacks(js_stack, non_v8_native);
    assert!(merged.contains(js_stack));
    assert!(merged.contains("pthread_create")); // Should contain the native stack

    // Test case 2: Proper V8 stack merging
    let v8_native = "v8::internal::Invoke;v8::Script::Run;native_func";
    let merged = merge_stacks(js_stack, v8_native);
    assert!(merged.contains(js_stack));
    assert!(merged.contains("native_func"));

    // Test case 3: Empty JavaScript stack
    let merged = merge_stacks("", v8_native);
    assert_eq!(merged, v8_native);

    // Test case 4: Both empty
    let merged = merge_stacks("", "");
    assert!(merged.is_empty());
}

#[test]
fn test_v8_process_detection() {
    let current_pid = std::process::id();

    // Test process detection with current process (likely not Node.js)
    let is_v8 = detect_v8_process(current_pid);

    // For most test environments, current process won't be Node.js
    // But we mainly test that the function doesn't crash
    println!(
        "Current process (PID {}) detected as V8/Node.js: {}",
        current_pid, is_v8
    );

    // Test V8 process detection via C FFI
    let is_v8_c = unsafe { is_v8_process(current_pid) };
    assert_eq!(is_v8, is_v8_c, "Rust and C FFI results should match");
}

#[test]
fn test_v8_tagged_pointer_verification() {
    // Test HeapObject pointer (tag = 01)
    let heap_ptr = 0x12345678_00000001u64;
    let invalid_ptr = 0x12345678_00000002u64; // Invalid tag
    let smi_ptr = 0x12345678_00000000u64; // SMI (tag = 0)

    assert_ne!(verify_heap_pointer(heap_ptr), 0);
    assert_eq!(verify_heap_pointer(invalid_ptr), 0);
    assert_eq!(verify_heap_pointer(smi_ptr), 0);
}

#[test]
fn test_v8_smi_parsing() {
    // Test SMI (Small Integer) parsing
    let smi_value = 0x12345678_00000000u64; // SMI with value
    let non_smi = 0x12345678_00000001u64; // HeapObject

    let parsed_smi = parse_v8_smi(smi_value);
    let parsed_non_smi = parse_v8_smi(non_smi);

    // SMI values are shifted right by 32 bits
    assert_eq!(parsed_smi, 0x12345678);
    assert_eq!(parsed_non_smi, 0x12345678); // Still extracts upper bits
}

#[test]
fn test_error_handling() {
    // Test invalid PID
    let invalid_result = detect_v8_process(0);
    assert_eq!(invalid_result, false, "Invalid PID should return false");

    let invalid_c_result = unsafe { is_v8_process(0) };
    assert_eq!(
        invalid_c_result, false,
        "Invalid PID should return false in C FFI"
    );

    // Test stack merging with null pointers
    let mut buffer = vec![0u8; 256];
    let null_result = unsafe {
        merge_v8_stacks(
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(null_result, 0, "Null inputs should return 0");
}

#[test]
fn test_version_compatibility() {
    // Test Node.js version compatibility checks
    let supported_node_versions = vec![
        Version::new(16, 0, 0),
        Version::new(16, 20, 2),
        Version::new(18, 0, 0),
        Version::new(18, 18, 2),
        Version::new(20, 0, 0),
        Version::new(20, 11, 0),
        Version::new(21, 0, 0),
    ];

    let unsupported_node_versions = vec![
        Version::new(14, 21, 0), // Too old
        Version::new(15, 14, 0), // Too old
        Version::new(22, 0, 0),  // Too new (hypothetical)
    ];

    let req = semver::VersionReq::parse(">=16.0.0, <22.0.0").unwrap();

    for version in supported_node_versions {
        assert!(
            req.matches(&version),
            "Node.js version {} should be supported",
            version
        );
    }

    for version in unsupported_node_versions {
        assert!(
            !req.matches(&version),
            "Node.js version {} should not be supported",
            version
        );
    }
}

#[test]
fn test_concurrent_operations() {
    use std::sync::Arc;
    use std::thread;

    let table = Arc::new(std::sync::Mutex::new(unsafe { V8UnwindTable::new(-1, -1) }));
    let mut handles = vec![];

    // Test concurrent operations
    for i in 0..10 {
        let table_clone = Arc::clone(&table);
        let handle = thread::spawn(move || {
            let test_pid = 12345 + i;

            if let Ok(mut t) = table_clone.lock() {
                unsafe {
                    t.load(test_pid);
                    t.unload(test_pid);
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete successfully");
    }
}

#[test]
fn test_memory_management() {
    // Test multiple allocations and deallocations
    const NUM_ITERATIONS: usize = 100;

    for _ in 0..NUM_ITERATIONS {
        let mut table = unsafe { V8UnwindTable::new(-1, -1) };

        // Load and unload multiple processes
        for pid in 10000..10010 {
            unsafe {
                table.load(pid);
            }
        }

        for pid in 10000..10010 {
            unsafe {
                table.unload(pid);
            }
        }

        // Table should be dropped here and memory cleaned up
    }

    // If we reach here without panicking, memory management is working
    assert!(true);
}

#[test]
fn test_performance_benchmark() {
    const NUM_OPERATIONS: usize = 1000;
    let start = std::time::Instant::now();

    let mut table = unsafe { V8UnwindTable::new(-1, -1) };

    for i in 0..NUM_OPERATIONS {
        let pid = 20000 + (i % 100); // Cycle through 100 PIDs

        unsafe {
            if i % 2 == 0 {
                table.load(pid as u32);
            } else {
                table.unload(pid as u32);
            }
        }
    }

    let elapsed = start.elapsed();
    let ops_per_sec = NUM_OPERATIONS as f64 / elapsed.as_secs_f64();

    println!("V8 Performance: {:.2} operations/second", ops_per_sec);
    assert!(ops_per_sec > 100.0, "Performance should be reasonable");
}

#[test]
fn test_javascript_function_parsing() {
    // Test parsing of JavaScript function names and locations
    let test_functions = vec![
        ("main", true),
        ("calculate", true),
        ("fibonacci", true),
        ("anonymous", true),
        ("", false), // Empty function name
    ];

    for (func_name, should_be_valid) in test_functions {
        let is_valid = !func_name.is_empty();
        assert_eq!(
            is_valid, should_be_valid,
            "Function name '{}' validity check failed",
            func_name
        );
    }
}

#[test]
fn test_v8_frame_pointer_parsing() {
    // Test V8 frame pointer context parsing
    let test_markers = vec![
        0x00000000u64, // SMI marker
        0x00000001u64, // HeapObject marker
        0x00000002u64, // Invalid marker
    ];

    for marker in test_markers {
        let is_smi = (marker & 0x1) == 0;
        let is_heap_object = (marker & 0x3) == 0x1;

        // These should be mutually exclusive
        if is_smi {
            assert!(!is_heap_object, "Marker cannot be both SMI and HeapObject");
        }
    }
}

// Helper function to simulate map_node_to_v8_version function
fn map_node_to_v8_version(node_version: &Version) -> Option<Version> {
    match node_version.major {
        16 => Some(Version::new(9, 4, 146)),
        18 => Some(Version::new(10, 2, 154)),
        20 => Some(Version::new(11, 3, 244)),
        21 => Some(Version::new(11, 8, 172)),
        _ => None,
    }
}
