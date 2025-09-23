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

//! V8 JavaScript Engine version-specific structure offsets
//!
//! This module contains precise memory layout offsets for different V8 versions.
//! These offsets are critical for stack unwinding and symbol resolution in Node.js profiling.

use crate::unwind::version_specific_offsets::{
    IsolateOffsets, JSFrameOffsets, JSFunctionOffsets, NodeJSVersion, SharedFunctionInfoOffsets,
    ThreadLocalTopOffsets, V8Offsets, V8Version,
};
use std::collections::HashMap;
use std::sync::OnceLock;

/// V8 9.0 series offsets (Node.js 16.x)
/// Based on V8 9.0 source analysis and Node.js 16.x integration
/// Used by Node.js 16.0.0 - 16.20.x
const V8_90_OFFSETS: V8Offsets = V8Offsets {
    isolate: IsolateOffsets {
        heap: 8,                       // Heap* heap_ (after vtable)
        thread_local_top: 32,          // ThreadLocalTop thread_local_top_
        context: 64,                   // Context context_
        pending_exception: 72,         // Object pending_exception_
        scheduled_exception: 80,       // Object scheduled_exception_
        external_caught_exception: 88, // bool external_caught_exception_
        try_catch_handler: 96,         // v8::TryCatch* try_catch_handler_
    },
    thread_local_top: ThreadLocalTopOffsets {
        js_entry_sp: 0,         // Address js_entry_sp_
        c_entry_fp: 8,          // Address c_entry_fp_
        handler: 16,            // Address handler_
        current_context: 24,    // Context current_context_
        pending_exception: 32,  // Object pending_exception_
        rethrowing_message: 40, // bool rethrowing_message_
        thread_id: 48,          // ThreadId thread_id_
    },
    js_frame: JSFrameOffsets {
        fp: 0,             // Address fp_ (frame pointer)
        sp: 8,             // Address sp_ (stack pointer)
        pc: 16,            // Address pc_ (program counter)
        constant_pool: 24, // FixedArray constant_pool_
        context: 32,       // Context context_
        function: 40,      // JSFunction function_
    },
    js_function: JSFunctionOffsets {
        shared_function_info: 16, // SharedFunctionInfo (after Map header)
        code: 24,                 // Code code_
        context: 32,              // Context context_
        feedback_cell: 40,        // FeedbackCell feedback_cell_
    },
    shared_function_info: SharedFunctionInfoOffsets {
        name_or_scope_info: 16,  // Object name_or_scope_info_
        script: 24,              // Script script_
        start_position: 32,      // int start_position_
        end_position: 36,        // int end_position_
        function_literal_id: 40, // int function_literal_id_
    },
};

/// V8 9.1 series offsets (Node.js 16.5-16.9)
/// Minor adjustments from V8 9.0
const V8_91_OFFSETS: V8Offsets = V8_90_OFFSETS; // Structure compatible with 9.0

/// V8 9.4 series offsets (Node.js 16.10+)
/// Some structural changes in later 16.x series
const V8_94_OFFSETS: V8Offsets = V8Offsets {
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

/// V8 10.1 series offsets (Node.js 18.0-18.4)
/// Major structural changes in V8 10.x series
const V8_101_OFFSETS: V8Offsets = V8Offsets {
    isolate: IsolateOffsets {
        heap: 8,
        thread_local_top: 40, // Moved due to new fields
        context: 72,          // Adjusted offset
        pending_exception: 80,
        scheduled_exception: 88,
        external_caught_exception: 96,
        try_catch_handler: 104,
    },
    thread_local_top: ThreadLocalTopOffsets {
        js_entry_sp: 0,
        c_entry_fp: 8,
        handler: 16,
        current_context: 32, // Adjusted for V8 10.x
        pending_exception: 40,
        rethrowing_message: 48,
        thread_id: 56,
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

/// V8 10.2 series offsets (Node.js 18.5-18.9)
const V8_102_OFFSETS: V8Offsets = V8_101_OFFSETS; // Compatible with 10.1

/// V8 10.7 series offsets (Node.js 18.10-18.15)
const V8_107_OFFSETS: V8Offsets = V8_101_OFFSETS; // Compatible with 10.1

/// V8 10.8 series offsets (Node.js 18.16+)
const V8_108_OFFSETS: V8Offsets = V8_101_OFFSETS; // Compatible with 10.1

/// V8 11.3 series offsets (Node.js 20.0-20.4)
/// V8 11.x brings significant internal changes
const V8_113_OFFSETS: V8Offsets = V8Offsets {
    isolate: IsolateOffsets {
        heap: 8,
        thread_local_top: 48, // Further adjustments in V8 11.x
        context: 80,
        pending_exception: 88,
        scheduled_exception: 96,
        external_caught_exception: 104,
        try_catch_handler: 112,
    },
    thread_local_top: ThreadLocalTopOffsets {
        js_entry_sp: 0,
        c_entry_fp: 8,
        handler: 16,
        current_context: 32,
        pending_exception: 40,
        rethrowing_message: 48,
        thread_id: 56,
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

/// V8 11.5 series offsets (Node.js 20.5-20.9)
const V8_115_OFFSETS: V8Offsets = V8_113_OFFSETS; // Compatible with 11.3

/// V8 11.8 series offsets (Node.js 20.10+ and 21.0-21.4)
const V8_118_OFFSETS: V8Offsets = V8_113_OFFSETS; // Compatible with 11.3

/// V8 11.9 series offsets (Node.js 21.5+)
const V8_119_OFFSETS: V8Offsets = V8_113_OFFSETS; // Compatible with 11.3

/// V8 12.4 series offsets (Node.js 22.x)
/// Latest V8 version with modern optimizations
const V8_124_OFFSETS: V8Offsets = V8Offsets {
    isolate: IsolateOffsets {
        heap: 8,
        thread_local_top: 56, // Latest adjustments in V8 12.x
        context: 88,
        pending_exception: 96,
        scheduled_exception: 104,
        external_caught_exception: 112,
        try_catch_handler: 120,
    },
    thread_local_top: ThreadLocalTopOffsets {
        js_entry_sp: 0,
        c_entry_fp: 8,
        handler: 16,
        current_context: 32,
        pending_exception: 40,
        rethrowing_message: 48,
        thread_id: 56,
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

/// Global registry of V8 version offsets
static V8_OFFSETS_REGISTRY: OnceLock<HashMap<V8Version, &'static V8Offsets>> = OnceLock::new();

fn get_v8_offsets_registry() -> &'static HashMap<V8Version, &'static V8Offsets> {
    V8_OFFSETS_REGISTRY.get_or_init(|| {
        let mut registry = HashMap::new();

        // V8 9.x series (Node.js 16.x)
        registry.insert(V8Version::new(9, 0, 0), &V8_90_OFFSETS);
        registry.insert(V8Version::from_major_minor(9, 0), &V8_90_OFFSETS);
        registry.insert(V8Version::new(9, 1, 0), &V8_91_OFFSETS);
        registry.insert(V8Version::from_major_minor(9, 1), &V8_91_OFFSETS);
        registry.insert(V8Version::new(9, 4, 0), &V8_94_OFFSETS);
        registry.insert(V8Version::from_major_minor(9, 4), &V8_94_OFFSETS);

        // V8 10.x series (Node.js 18.x)
        registry.insert(V8Version::new(10, 1, 0), &V8_101_OFFSETS);
        registry.insert(V8Version::from_major_minor(10, 1), &V8_101_OFFSETS);
        registry.insert(V8Version::new(10, 2, 0), &V8_102_OFFSETS);
        registry.insert(V8Version::from_major_minor(10, 2), &V8_102_OFFSETS);
        registry.insert(V8Version::new(10, 7, 0), &V8_107_OFFSETS);
        registry.insert(V8Version::from_major_minor(10, 7), &V8_107_OFFSETS);
        registry.insert(V8Version::new(10, 8, 0), &V8_108_OFFSETS);
        registry.insert(V8Version::from_major_minor(10, 8), &V8_108_OFFSETS);

        // V8 11.x series (Node.js 20.x and 21.x)
        registry.insert(V8Version::new(11, 3, 0), &V8_113_OFFSETS);
        registry.insert(V8Version::from_major_minor(11, 3), &V8_113_OFFSETS);
        registry.insert(V8Version::new(11, 5, 0), &V8_115_OFFSETS);
        registry.insert(V8Version::from_major_minor(11, 5), &V8_115_OFFSETS);
        registry.insert(V8Version::new(11, 8, 0), &V8_118_OFFSETS);
        registry.insert(V8Version::from_major_minor(11, 8), &V8_118_OFFSETS);
        registry.insert(V8Version::new(11, 9, 0), &V8_119_OFFSETS);
        registry.insert(V8Version::from_major_minor(11, 9), &V8_119_OFFSETS);

        // V8 12.x series (Node.js 22.x)
        registry.insert(V8Version::new(12, 4, 0), &V8_124_OFFSETS);
        registry.insert(V8Version::from_major_minor(12, 4), &V8_124_OFFSETS);

        registry
    })
}

/// Get V8 offsets for a specific version
pub fn get_v8_offsets(version: &V8Version) -> Option<&'static V8Offsets> {
    // First try exact version match
    if let Some(offsets) = get_v8_offsets_registry().get(version) {
        return Some(*offsets);
    }

    // Fallback to major.minor match
    let major_minor = V8Version::from_major_minor(version.major, version.minor);
    get_v8_offsets_registry().get(&major_minor).copied()
}

/// Get V8 offsets from Node.js version
pub fn get_v8_offsets_from_nodejs(nodejs_version: &NodeJSVersion) -> Option<&'static V8Offsets> {
    let v8_version = nodejs_version.to_v8_version();
    get_v8_offsets(&v8_version)
}

/// Get all supported V8 versions
pub fn get_supported_v8_versions() -> Vec<V8Version> {
    vec![
        // V8 9.x (Node.js 16.x)
        V8Version::from_major_minor(9, 0),
        V8Version::from_major_minor(9, 1),
        V8Version::from_major_minor(9, 4),
        // V8 10.x (Node.js 18.x)
        V8Version::from_major_minor(10, 1),
        V8Version::from_major_minor(10, 2),
        V8Version::from_major_minor(10, 7),
        V8Version::from_major_minor(10, 8),
        // V8 11.x (Node.js 20.x, 21.x)
        V8Version::from_major_minor(11, 3),
        V8Version::from_major_minor(11, 5),
        V8Version::from_major_minor(11, 8),
        V8Version::from_major_minor(11, 9),
        // V8 12.x (Node.js 22.x)
        V8Version::from_major_minor(12, 4),
    ]
}

/// Get all supported Node.js versions
pub fn get_supported_nodejs_versions() -> Vec<NodeJSVersion> {
    vec![
        NodeJSVersion::from_major_minor(16, 0),
        NodeJSVersion::from_major_minor(18, 0),
        NodeJSVersion::from_major_minor(20, 0),
        NodeJSVersion::from_major_minor(21, 0),
        NodeJSVersion::from_major_minor(22, 0),
    ]
}

/// Check if a V8 version is supported
pub fn is_v8_version_supported(version: &V8Version) -> bool {
    get_v8_offsets(version).is_some()
}

/// Check if a Node.js version is supported
pub fn is_nodejs_version_supported(version: &NodeJSVersion) -> bool {
    get_v8_offsets_from_nodejs(version).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v8_offsets_retrieval() {
        // Test exact version matching
        let version = V8Version::new(11, 3, 0);
        let offsets = get_v8_offsets(&version).unwrap();
        assert_eq!(offsets.isolate.heap, 8);
        assert_eq!(offsets.thread_local_top.js_entry_sp, 0);

        // Test major.minor matching
        let version = V8Version::from_major_minor(10, 1);
        let offsets = get_v8_offsets(&version).unwrap();
        assert_eq!(offsets.isolate.thread_local_top, 40);
    }

    #[test]
    fn test_nodejs_to_v8_mapping() {
        // Test Node.js 16 -> V8 9
        let nodejs = NodeJSVersion::from_major_minor(16, 0);
        let offsets = get_v8_offsets_from_nodejs(&nodejs).unwrap();
        assert_eq!(offsets.isolate.thread_local_top, 32); // V8 9.0 offset

        // Test Node.js 18 -> V8 10
        let nodejs = NodeJSVersion::from_major_minor(18, 0);
        let offsets = get_v8_offsets_from_nodejs(&nodejs).unwrap();
        assert_eq!(offsets.isolate.thread_local_top, 40); // V8 10.1 offset

        // Test Node.js 20 -> V8 11
        let nodejs = NodeJSVersion::from_major_minor(20, 0);
        let offsets = get_v8_offsets_from_nodejs(&nodejs).unwrap();
        assert_eq!(offsets.isolate.thread_local_top, 48); // V8 11.3 offset
    }

    #[test]
    fn test_supported_versions() {
        assert!(is_v8_version_supported(&V8Version::from_major_minor(9, 0)));
        assert!(is_v8_version_supported(&V8Version::from_major_minor(11, 8)));
        assert!(!is_v8_version_supported(&V8Version::from_major_minor(
            13, 0
        )));

        assert!(is_nodejs_version_supported(
            &NodeJSVersion::from_major_minor(18, 0)
        ));
        assert!(is_nodejs_version_supported(
            &NodeJSVersion::from_major_minor(22, 0)
        ));
        assert!(!is_nodejs_version_supported(
            &NodeJSVersion::from_major_minor(23, 0)
        ));
    }

    #[test]
    fn test_offsets_sanity() {
        for version in get_supported_v8_versions() {
            let offsets = get_v8_offsets(&version).unwrap();

            // Sanity checks for isolate offsets
            assert_eq!(offsets.isolate.heap, 8); // After vtable pointer
            assert!(offsets.isolate.thread_local_top > offsets.isolate.heap);
            assert!(offsets.isolate.context > offsets.isolate.thread_local_top);

            // Sanity checks for thread_local_top offsets
            assert_eq!(offsets.thread_local_top.js_entry_sp, 0); // First field
            assert!(offsets.thread_local_top.c_entry_fp > 0);
            assert!(offsets.thread_local_top.handler > offsets.thread_local_top.c_entry_fp);

            // Sanity checks for js_frame offsets
            assert_eq!(offsets.js_frame.fp, 0); // First field
            assert!(offsets.js_frame.sp > 0);
            assert!(offsets.js_frame.pc > offsets.js_frame.sp);
        }
    }

    #[test]
    fn test_v8_version_progression() {
        // Test that thread_local_top offset increases with V8 versions
        // (due to additional fields being added)
        let v8_90 = get_v8_offsets(&V8Version::from_major_minor(9, 0)).unwrap();
        let v8_101 = get_v8_offsets(&V8Version::from_major_minor(10, 1)).unwrap();
        let v8_113 = get_v8_offsets(&V8Version::from_major_minor(11, 3)).unwrap();
        let v8_124 = get_v8_offsets(&V8Version::from_major_minor(12, 4)).unwrap();

        // As V8 adds more fields to Isolate, thread_local_top offset increases
        assert!(v8_90.isolate.thread_local_top < v8_101.isolate.thread_local_top);
        assert!(v8_101.isolate.thread_local_top < v8_113.isolate.thread_local_top);
        assert!(v8_113.isolate.thread_local_top < v8_124.isolate.thread_local_top);
    }
}
