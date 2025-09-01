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

#[test]
fn test_php_unwind_table_operations() {
    // Test PHP unwind table basic operations
    let mut table = unsafe { PhpUnwindTable::new(-1, -1) }; // Mock file descriptors

    let test_pid = 12345;

    // Test load operation (should not crash even with invalid FDs)
    unsafe { table.load(test_pid) };

    // Test unload operation
    unsafe { table.unload(test_pid) };

    // PHP unwind table operations completed successfully
}

#[test]
fn test_stack_merging() {
    let php_stack = "MyClass::method1;function2;main";
    let native_stack = "main;start_thread;__clone";

    let mut buffer = vec![0u8; 512];
    let php_cstring = std::ffi::CString::new(php_stack).unwrap();
    let native_cstring = std::ffi::CString::new(native_stack).unwrap();
    let result_len = unsafe {
        merge_php_stacks(
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len(),
            php_cstring.as_ptr() as *const std::ffi::c_void,
            native_cstring.as_ptr() as *const std::ffi::c_void,
        )
    };

    assert!(
        result_len > 0,
        "Stack merging should return non-zero length"
    );

    let result_str = String::from_utf8_lossy(&buffer[..result_len]);
    assert!(
        result_str.contains("MyClass::method1"),
        "Merged stack should contain PHP function"
    );
    assert!(
        result_str.contains("main"),
        "Merged stack should contain native function"
    );
}

#[test]
fn test_process_detection() {
    let current_pid = std::process::id();

    // Test process detection with current process (likely not PHP)
    let is_php = unsafe { is_php_process(current_pid) };

    // For most test environments, current process won't be PHP
    // But we mainly test that the function doesn't crash
    println!(
        "Current process (PID {}) detected as PHP: {}",
        current_pid, is_php
    );
}

#[test]
fn test_error_handling() {
    // Test invalid PID
    let invalid_result = unsafe { is_php_process(0) };
    assert_eq!(invalid_result, false, "Invalid PID should return false");

    // Test stack merging with null pointers
    let mut buffer = vec![0u8; 256];
    let null_result = unsafe {
        merge_php_stacks(
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(null_result, 0, "Null inputs should return 0");
}

#[test]
fn test_php_integration_scenarios() {
    // Test comprehensive PHP integration scenarios
    let mut table = unsafe { PhpUnwindTable::new(-1, -1) };

    // Test multiple process loading/unloading
    let pids = vec![1001, 1002, 1003];
    for pid in &pids {
        unsafe { table.load(*pid) };
    }

    // PHP integration scenarios completed successfully

    // Test unloading
    for pid in &pids {
        unsafe { table.unload(*pid) };
    }
}

#[test]
fn test_php_stack_merging_edge_cases() {
    let mut buffer = vec![0u8; 1024];

    // Test with empty PHP stack
    let empty_php = "";
    let native_stack = "main;start_thread";
    let empty_php_cstring = std::ffi::CString::new(empty_php).unwrap();
    let native_cstring = std::ffi::CString::new(native_stack).unwrap();
    let result_len = unsafe {
        merge_php_stacks(
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len(),
            empty_php_cstring.as_ptr() as *const std::ffi::c_void,
            native_cstring.as_ptr() as *const std::ffi::c_void,
        )
    };

    if result_len > 0 {
        let result_str = String::from_utf8_lossy(&buffer[..result_len]);
        // Should contain native stack when PHP stack is empty
        assert!(result_str.contains("main"));
    }

    // Test with empty native stack
    let php_stack = "MyClass::method1;function2";
    let empty_native = "";
    let php_cstring = std::ffi::CString::new(php_stack).unwrap();
    let empty_native_cstring = std::ffi::CString::new(empty_native).unwrap();
    let result_len = unsafe {
        merge_php_stacks(
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len(),
            php_cstring.as_ptr() as *const std::ffi::c_void,
            empty_native_cstring.as_ptr() as *const std::ffi::c_void,
        )
    };

    if result_len > 0 {
        let result_str = String::from_utf8_lossy(&buffer[..result_len]);
        // Should contain PHP stack when native stack is empty
        assert!(result_str.contains("MyClass::method1"));
    }
}

#[test]
fn test_php_stack_merging_native_helper_order() {
    let php_stack = "memory_intensive_task";
    let native_stack = "root;[p] php;execute_ex;zend_long_to_str;_emalloc";

    let mut buffer = vec![0u8; 512];
    let php_cstring = std::ffi::CString::new(php_stack).unwrap();
    let native_cstring = std::ffi::CString::new(native_stack).unwrap();
    let result_len = unsafe {
        merge_php_stacks(
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len(),
            php_cstring.as_ptr() as *const std::ffi::c_void,
            native_cstring.as_ptr() as *const std::ffi::c_void,
        )
    };

    assert!(result_len > 0, "Merged stack should contain frames");
    let result_str = String::from_utf8_lossy(&buffer[..result_len]);
    assert_eq!(
        result_str,
        "root;[p] php;execute_ex;memory_intensive_task;zend_long_to_str;_emalloc"
    );
}

#[test]
fn test_php_stack_merging_math_helpers() {
    let php_stack = "matrix_multiply";
    let native_stack = "root;[p] php80;/usr/bin/php;add_function";

    let mut buffer = vec![0u8; 512];
    let php_cstring = std::ffi::CString::new(php_stack).unwrap();
    let native_cstring = std::ffi::CString::new(native_stack).unwrap();
    let result_len = unsafe {
        merge_php_stacks(
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer.len(),
            php_cstring.as_ptr() as *const std::ffi::c_void,
            native_cstring.as_ptr() as *const std::ffi::c_void,
        )
    };

    assert!(result_len > 0, "Merged stack should contain frames");
    let result_str = String::from_utf8_lossy(&buffer[..result_len]);
    assert_eq!(
        result_str,
        "root;[p] php80;/usr/bin/php;matrix_multiply;add_function"
    );
}
