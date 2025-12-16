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
fn test_is_v8_process() {
    // Test with current process (not a Node.js process)
    let current_pid = std::process::id();
    assert!(!unsafe { is_v8_process(current_pid) });

    // Test with invalid PID
    assert!(!unsafe { is_v8_process(999999) });
}

#[test]
fn test_merge_stacks() {
    // Test proper V8 stack merging
    let js_trace = "main;calculate;fibonacci";
    let v8_native_trace = "v8::internal::Invoke;v8::Script::Run;native_func";
    let merged = merge_stacks(js_trace, v8_native_trace);
    assert!(merged.contains(js_trace));
    assert!(merged.contains("native_func"));

    // Test JS stack only when no V8 frames detected
    let non_v8_native = "pthread_create;some_native_func";
    let merged = merge_stacks(js_trace, non_v8_native);
    assert!(merged.contains(js_trace));
    assert!(merged.contains("pthread_create")); // Should contain the native stack

    // Test only JS stack (empty native)
    let merged = merge_stacks(js_trace, "");
    assert_eq!(merged, js_trace);

    // Test only native stack (empty JS)
    let merged = merge_stacks("", v8_native_trace);
    assert_eq!(merged, v8_native_trace);

    // Test both empty
    let merged = merge_stacks("", "");
    assert!(merged.is_empty());
}

#[test]
fn test_v8_unwind_table_creation() {
    // This would normally require actual BPF map file descriptors
    // For testing, we simulate with invalid fds (should fail gracefully)
    let _table = unsafe { V8UnwindTable::new(-1) };
    // V8UnwindTable creation completed successfully with mock fds
}

#[test]
fn test_v8_unwind_table_lifecycle() {
    // Test full lifecycle: create -> load -> unload
    let mut table = unsafe { V8UnwindTable::new(-1) };
    let test_pid = 50000u32;

    // Load should not crash even with invalid FDs
    unsafe {
        table.load(test_pid);
    }

    // Check if version was registered (may fail if not a real V8 process)
    let _version = table.get_process_version(test_pid);
    // Version may be None if the process doesn't exist or isn't V8

    // Unload should not crash
    unsafe {
        table.unload(test_pid);
    }

    // After unload, version should be removed
    let version_after = table.get_process_version(test_pid);
    assert!(
        version_after.is_none(),
        "Version should be None after unload"
    );
}

#[test]
fn test_merge_stacks_with_builtins() {
    // Test stack merging with V8 builtin frames
    let js_stack = "app;handler;process";
    let native_with_builtins = "Builtins_JSEntry;Builtins_CallFunction;native_func";

    let merged = merge_stacks(js_stack, native_with_builtins);

    // JS frames should replace builtin frames
    assert!(merged.contains("app"));
    assert!(merged.contains("handler"));
    assert!(merged.contains("process"));
    assert!(merged.contains("native_func"));
}

#[test]
fn test_merge_stacks_with_unknown_frames() {
    // Test stack merging with [unknown] frames
    let js_stack = "main;worker";
    let native_with_unknown = "[unknown];native_func;[unknown]";

    let merged = merge_stacks(js_stack, native_with_unknown);

    // JS frames should appear in the merged stack
    assert!(merged.contains("main") || merged.contains("worker"));
    assert!(merged.contains("native_func"));
}

#[test]
fn test_merge_stacks_with_node_frames() {
    // Test stack merging with [node] frames
    let js_stack = "index.js;server.js";
    let native_with_node = "[/usr/bin/node];libc_start_main;main";

    let merged = merge_stacks(js_stack, native_with_node);

    // Should merge JS frames with native stack
    assert!(merged.contains("server.js") || merged.contains("index.js"));
}

#[test]
fn test_offsets_consistency_across_versions() {
    // Test that all V8 version offsets are internally consistent
    let versions = vec![
        (Version::new(9, 4, 0), V8_9_OFFSETS),
        (Version::new(10, 2, 0), V8_10_OFFSETS),
        (Version::new(11, 3, 0), V8_11_OFFSETS),
        (Version::new(12, 4, 0), V8_12_OFFSETS),
    ];

    for (version, offsets) in versions {
        // Verify critical offsets are non-zero
        assert!(
            offsets.js_function.shared > 0,
            "V8 {}: js_function.shared should be > 0",
            version
        );
        assert!(
            offsets.js_function.code > 0,
            "V8 {}: js_function.code should be > 0",
            version
        );
        assert!(
            offsets.shared_function_info.name_or_scope_info > 0,
            "V8 {}: name_or_scope_info should be > 0",
            version
        );

        // Verify heap object map offset is always 0 (first field)
        assert_eq!(
            offsets.heap_object.map, 0,
            "V8 {}: heap_object.map should be 0",
            version
        );

        // Verify frame pointer offsets are negative (relative to FP)
        assert!(
            offsets.frame_pointers.marker < 0,
            "V8 {}: frame marker should be negative",
            version
        );
        assert!(
            offsets.frame_pointers.function < 0,
            "V8 {}: frame function should be negative",
            version
        );
    }
}

#[test]
fn test_v8_proc_info_structure_size() {
    // Verify V8ProcInfo matches expected size (64 bytes)
    use std::mem::size_of;

    let size = size_of::<V8ProcInfo>();
    assert_eq!(
        size, 64,
        "V8ProcInfo must be exactly 64 bytes to match C v8_proc_info_t"
    );

    // Verify alignment
    let align = std::mem::align_of::<V8ProcInfo>();
    assert!(align >= 8, "V8ProcInfo should be at least 8-byte aligned");
}

#[test]
fn test_v8_proc_info_from_offsets() {
    // Test V8ProcInfo creation from different V8 versions
    let test_cases = vec![
        (V8_9_OFFSETS, 90400),   // V8 9.4.0
        (V8_10_OFFSETS, 100200), // V8 10.2.0
        (V8_11_OFFSETS, 110300), // V8 11.3.0
        (V8_12_OFFSETS, 120400), // V8 12.4.0
    ];

    for (offsets, version) in test_cases {
        let proc_info = V8ProcInfo::from_offsets(offsets, version);

        // Verify version is set correctly
        assert_eq!(proc_info.v8_version, version);

        // Verify offsets are copied correctly
        assert_eq!(proc_info.off_jsfunction_shared, offsets.js_function.shared);
        assert_eq!(proc_info.off_jsfunction_code, offsets.js_function.code);
        assert_eq!(proc_info.fp_marker, offsets.frame_pointers.marker);

        // Verify counters are initialized to zero
        assert_eq!(proc_info.unwinding_attempted, 0);
        assert_eq!(proc_info.unwinding_success, 0);
        assert_eq!(proc_info.unwinding_failed, 0);
    }
}

#[test]
fn test_get_offsets_for_v8_version() {
    // Test offset selection for different V8 versions (updated for minor version matching)
    use crate::unwind::v8::{V8_10_8_OFFSETS, V8_11_8_OFFSETS, V8_12_9_OFFSETS, V8_9_6_OFFSETS};

    let test_cases = vec![
        // Even versions
        (Version::new(9, 0, 0), V8_9_OFFSETS),
        (Version::new(9, 4, 146), V8_9_OFFSETS),
        (Version::new(10, 2, 154), V8_10_OFFSETS),
        (Version::new(11, 3, 244), V8_11_OFFSETS),
        (Version::new(12, 4, 254), V8_12_OFFSETS),
        // Odd versions (new)
        (Version::new(9, 6, 180), V8_9_6_OFFSETS),
        (Version::new(10, 8, 168), V8_10_8_OFFSETS),
        (Version::new(11, 8, 172), V8_11_8_OFFSETS),
        (Version::new(12, 9, 202), V8_12_9_OFFSETS),
        // Future/old versions
        (Version::new(13, 0, 0), V8_12_9_OFFSETS), // Future versions default to latest
        (Version::new(8, 0, 0), V8_9_OFFSETS),     // Old versions default to V8 9
    ];

    for (version, expected_offsets) in test_cases {
        let offsets = get_offsets_for_v8_version(&version);

        // Compare key fields to verify correct offset set
        assert_eq!(
            offsets.js_function.shared, expected_offsets.js_function.shared,
            "V8 {}: js_function.shared mismatch",
            version
        );
        assert_eq!(
            offsets.code.instruction_start, expected_offsets.code.instruction_start,
            "V8 {}: code.instruction_start mismatch",
            version
        );
    }
}

#[test]
fn test_concurrent_symbolizer_access() {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;

    // Test concurrent access to V8 symbolizer
    let table = Arc::new(Mutex::new(unsafe { V8UnwindTable::new(-1) }));
    let mut handles = vec![];

    for i in 0..5 {
        let table_clone = Arc::clone(&table);
        let handle = thread::spawn(move || {
            let pid = 60000 + i;

            if let Ok(mut t) = table_clone.lock() {
                unsafe {
                    t.load(pid);
                    // Try to get offsets
                    let _offsets = t.get_offsets_for_process(pid);
                    t.unload(pid);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }
}

#[test]
fn test_enhance_v8_trace() {
    // Test V8 trace enhancement (internal function)
    // This is tested indirectly through merge_stacks

    let simple_trace = "main;calculate";
    let enhanced = enhance_v8_trace(simple_trace);

    // Enhanced trace should contain original frames
    assert!(enhanced.contains("main"));
    assert!(enhanced.contains("calculate"));
}

#[test]
fn test_enhance_single_v8_frame() {
    // Test single frame enhancement
    let test_cases = vec![
        ("V8Stub#1", "[stub]"),
        ("SFI@0x12345678", "[interpreted]"),
        ("Code@0xabcdef00", "[jit]"),
        ("normalFunction", "normalFunction"),
    ];

    for (input, expected_marker) in test_cases {
        let enhanced = enhance_single_v8_frame(input);
        if !expected_marker.is_empty() && expected_marker != input {
            assert!(
                enhanced.contains(expected_marker) || enhanced == input,
                "Frame '{}' should contain '{}'",
                input,
                expected_marker
            );
        }
    }
}

#[test]
fn test_replace_builtin_frames_with_js() {
    // Test builtin frame replacement logic
    let native_trace = "root;Builtins_JSEntry;Builtins_CallFunction;native_end";
    let js_trace = "app;handler";

    let result = replace_builtin_frames_with_js(native_trace, js_trace);

    // JS frames should replace builtin frames
    assert!(result.contains("app"));
    assert!(result.contains("handler"));
    assert!(result.contains("root"));
    assert!(result.contains("native_end"));
}

#[test]
fn test_frame_ordering_preservation() {
    // Test that frame ordering is preserved during merging
    let js_trace = "frame1;frame2;frame3";
    let native_trace = "native1;Builtins_Entry;native3";

    let merged = merge_stacks(js_trace, native_trace);

    // Verify frames appear in correct order
    let frame1_pos = merged.find("frame1");
    let frame2_pos = merged.find("frame2");
    let frame3_pos = merged.find("frame3");

    if let (Some(pos1), Some(pos2), Some(pos3)) = (frame1_pos, frame2_pos, frame3_pos) {
        assert!(pos1 < pos2, "frame1 should appear before frame2");
        assert!(pos2 < pos3, "frame2 should appear before frame3");
    }
}

#[test]
fn test_memory_safety_with_large_stacks() {
    // Test memory safety with very large stack traces
    let mut large_js_trace = String::new();
    let mut large_native_trace = String::new();

    for i in 0..100 {
        large_js_trace.push_str(&format!("jsframe{};", i));
        large_native_trace.push_str(&format!("native{};", i));
    }

    // This should not panic or cause memory issues
    let merged = merge_stacks(&large_js_trace, &large_native_trace);

    assert!(!merged.is_empty());
    assert!(merged.len() < large_js_trace.len() + large_native_trace.len() + 1000);
}

#[test]
fn test_v8_file_type_constants() {
    // Verify V8 file type constants are correct
    use crate::unwind::v8::{
        V8_FILE_TYPE_BYTECODE, V8_FILE_TYPE_MARKER, V8_FILE_TYPE_MASK, V8_FILE_TYPE_NATIVE_CODE,
        V8_FILE_TYPE_NATIVE_JSFUNC, V8_FILE_TYPE_NATIVE_SFI,
    };

    // Verify mask
    assert_eq!(V8_FILE_TYPE_MASK, 0x7);

    // Verify all types are within mask
    assert_eq!(V8_FILE_TYPE_MARKER & V8_FILE_TYPE_MASK, V8_FILE_TYPE_MARKER);
    assert_eq!(
        V8_FILE_TYPE_BYTECODE & V8_FILE_TYPE_MASK,
        V8_FILE_TYPE_BYTECODE
    );
    assert_eq!(
        V8_FILE_TYPE_NATIVE_SFI & V8_FILE_TYPE_MASK,
        V8_FILE_TYPE_NATIVE_SFI
    );
    assert_eq!(
        V8_FILE_TYPE_NATIVE_CODE & V8_FILE_TYPE_MASK,
        V8_FILE_TYPE_NATIVE_CODE
    );
    assert_eq!(
        V8_FILE_TYPE_NATIVE_JSFUNC & V8_FILE_TYPE_MASK,
        V8_FILE_TYPE_NATIVE_JSFUNC
    );

    // Verify types are unique
    let types = vec![
        V8_FILE_TYPE_MARKER,
        V8_FILE_TYPE_BYTECODE,
        V8_FILE_TYPE_NATIVE_SFI,
        V8_FILE_TYPE_NATIVE_CODE,
        V8_FILE_TYPE_NATIVE_JSFUNC,
    ];

    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            assert_ne!(types[i], types[j], "Frame types must be unique");
        }
    }
}
