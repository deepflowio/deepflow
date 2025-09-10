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
fn test_is_v8_process() {
    // Test with current process (not a Node.js process)
    let current_pid = std::process::id();
    assert!(!detect_v8_process(current_pid));

    // Test with invalid PID
    assert!(!detect_v8_process(999999));
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
    assert!(merged.contains(INCOMPLETE_V8_STACK));

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
    let _table = unsafe { V8UnwindTable::new(-1, -1) };
    // V8UnwindTable creation completed successfully with mock fds
}
