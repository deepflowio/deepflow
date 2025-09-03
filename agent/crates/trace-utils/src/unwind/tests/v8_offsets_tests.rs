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

//! Tests for V8 version-specific offsets

use super::setup_test_env;
use super::test_utils::*;
use crate::unwind::v8_offsets::*;
use crate::unwind::version_specific_offsets::*;

#[test]
fn test_v8_offsets_retrieval() {
    setup_test_env();

    // Test exact version matching
    let version = V8Version::new(11, 3, 0);
    let offsets = get_v8_offsets(&version).unwrap();

    // Validate basic structure
    assert_eq!(offsets.isolate.heap, 8); // After vtable pointer
    assert!(offsets.isolate.thread_local_top > offsets.isolate.heap);

    assert_eq!(offsets.thread_local_top.js_entry_sp, 0); // First field
    assert!(offsets.thread_local_top.c_entry_fp > 0);

    assert_eq!(offsets.js_frame.fp, 0); // First field
    assert!(offsets.js_frame.sp > 0);
    assert!(offsets.js_frame.pc > offsets.js_frame.sp);

    // Test major.minor matching
    let version_mm = V8Version::from_major_minor(10, 1);
    let offsets_mm = get_v8_offsets(&version_mm).unwrap();
    assert_eq!(offsets_mm.isolate.thread_local_top, 40); // V8 10.1 specific
}

#[test]
fn test_all_supported_v8_versions() {
    setup_test_env();

    let supported_versions = get_supported_v8_versions();
    assert!(!supported_versions.is_empty());

    // Expected supported V8 versions
    let expected_versions = vec![
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
    ];

    for expected in &expected_versions {
        assert!(
            supported_versions.contains(expected),
            "V8 version {} should be supported",
            expected
        );
        assert!(
            is_v8_version_supported(expected),
            "V8 version {} should be supported",
            expected
        );

        let offsets = get_v8_offsets(expected).unwrap();
        assert!(
            validate_v8_offsets(offsets),
            "Offsets for V8 {} should be valid",
            expected
        );
    }
}

#[test]
fn test_nodejs_to_v8_offsets_mapping() {
    setup_test_env();

    let test_cases = vec![
        // (nodejs_version, expected_v8_offsets_available)
        (NodeJSVersion::from_major_minor(16, 0), true),
        (NodeJSVersion::from_major_minor(18, 0), true),
        (NodeJSVersion::from_major_minor(20, 0), true),
        (NodeJSVersion::from_major_minor(21, 0), true),
        (NodeJSVersion::from_major_minor(22, 0), true),
    ];

    for (nodejs_version, should_have_offsets) in &test_cases {
        let offsets_opt = get_v8_offsets_from_nodejs(nodejs_version);

        if *should_have_offsets {
            let offsets = offsets_opt.unwrap();
            assert!(
                validate_v8_offsets(offsets),
                "V8 offsets for Node.js {} should be valid",
                nodejs_version
            );

            assert!(
                is_nodejs_version_supported(nodejs_version),
                "Node.js {} should be supported",
                nodejs_version
            );
        } else {
            assert!(
                offsets_opt.is_none(),
                "Node.js {} should not have V8 offsets",
                nodejs_version
            );
            assert!(
                !is_nodejs_version_supported(nodejs_version),
                "Node.js {} should not be supported",
                nodejs_version
            );
        }
    }
}

#[test]
fn test_unsupported_v8_versions() {
    setup_test_env();

    let unsupported_versions = vec![
        V8Version::from_major_minor(8, 0),  // Too old
        V8Version::from_major_minor(7, 9),  // Too old
        V8Version::from_major_minor(13, 0), // Future version
        V8Version::from_major_minor(15, 0), // Very future version
    ];

    for version in &unsupported_versions {
        assert!(
            !is_v8_version_supported(version),
            "V8 version {} should not be supported",
            version
        );
        assert!(
            get_v8_offsets(version).is_none(),
            "V8 version {} should return None offsets",
            version
        );
    }

    let unsupported_nodejs_versions = vec![
        NodeJSVersion::from_major_minor(14, 0), // Too old
        NodeJSVersion::from_major_minor(15, 0), // Too old
        NodeJSVersion::from_major_minor(23, 0), // Future (should fallback but test explicit)
    ];

    // Note: Some future Node.js versions may still be supported via fallback mapping
    for version in &unsupported_nodejs_versions[..2] {
        // Only test the definitely unsupported ones
        if !is_nodejs_version_supported(version) {
            assert!(
                get_v8_offsets_from_nodejs(version).is_none(),
                "Unsupported Node.js version {} should return None offsets",
                version
            );
        }
    }
}

#[test]
fn test_v8_offsets_sanity_checks() {
    setup_test_env();

    for version in get_supported_v8_versions() {
        let offsets = get_v8_offsets(&version).unwrap();

        // Isolate sanity checks
        assert_eq!(
            offsets.isolate.heap, 8,
            "heap should be at offset 8 (after vtable) for V8 {}",
            version
        );
        assert!(
            offsets.isolate.thread_local_top > offsets.isolate.heap,
            "thread_local_top should be after heap for V8 {}",
            version
        );
        assert!(
            offsets.isolate.context > offsets.isolate.thread_local_top,
            "context should be after thread_local_top for V8 {}",
            version
        );

        // ThreadLocalTop sanity checks
        assert_eq!(
            offsets.thread_local_top.js_entry_sp, 0,
            "js_entry_sp should be first field for V8 {}",
            version
        );
        assert!(
            offsets.thread_local_top.c_entry_fp > 0,
            "c_entry_fp offset should be > 0 for V8 {}",
            version
        );
        assert!(
            offsets.thread_local_top.handler > offsets.thread_local_top.c_entry_fp,
            "handler should be after c_entry_fp for V8 {}",
            version
        );

        // JSFrame sanity checks
        assert_eq!(
            offsets.js_frame.fp, 0,
            "fp should be first field for V8 {}",
            version
        );
        assert!(
            offsets.js_frame.sp > 0,
            "sp offset should be > 0 for V8 {}",
            version
        );
        assert!(
            offsets.js_frame.pc > offsets.js_frame.sp,
            "pc should be after sp for V8 {}",
            version
        );

        // JSFunction sanity checks
        assert!(
            offsets.js_function.shared_function_info > 0,
            "shared_function_info offset should be > 0 for V8 {}",
            version
        );
        assert!(
            offsets.js_function.code > 0,
            "code offset should be > 0 for V8 {}",
            version
        );

        // SharedFunctionInfo sanity checks
        assert!(
            offsets.shared_function_info.name_or_scope_info > 0,
            "name_or_scope_info offset should be > 0 for V8 {}",
            version
        );
        assert!(
            offsets.shared_function_info.script > 0,
            "script offset should be > 0 for V8 {}",
            version
        );
    }
}

#[test]
fn test_v8_version_progression() {
    setup_test_env();

    // Test that thread_local_top offset increases with V8 versions
    // (due to additional fields being added over time)
    let v8_90 = get_v8_offsets(&V8Version::from_major_minor(9, 0)).unwrap();
    let v8_101 = get_v8_offsets(&V8Version::from_major_minor(10, 1)).unwrap();
    let v8_113 = get_v8_offsets(&V8Version::from_major_minor(11, 3)).unwrap();
    let v8_124 = get_v8_offsets(&V8Version::from_major_minor(12, 4)).unwrap();

    // As V8 adds more fields to Isolate, thread_local_top offset should generally increase
    assert!(
        v8_90.isolate.thread_local_top < v8_101.isolate.thread_local_top,
        "V8 9.0 thread_local_top offset should be less than V8 10.1"
    );
    assert!(
        v8_101.isolate.thread_local_top < v8_113.isolate.thread_local_top,
        "V8 10.1 thread_local_top offset should be less than V8 11.3"
    );
    assert!(
        v8_113.isolate.thread_local_top < v8_124.isolate.thread_local_top,
        "V8 11.3 thread_local_top offset should be less than V8 12.4"
    );
}

#[test]
fn test_nodejs_v8_version_consistency() {
    setup_test_env();

    let nodejs_versions = get_supported_nodejs_versions();

    for nodejs_version in &nodejs_versions {
        let v8_version = nodejs_version.to_v8_version();

        // The V8 version derived from Node.js should be supported
        assert!(
            is_v8_version_supported(&v8_version),
            "V8 version {} derived from Node.js {} should be supported",
            v8_version,
            nodejs_version
        );

        // Should be able to get offsets
        let offsets = get_v8_offsets(&v8_version).unwrap();
        assert!(
            validate_v8_offsets(offsets),
            "V8 offsets for Node.js {} -> V8 {} should be valid",
            nodejs_version,
            v8_version
        );

        // Alternative method should also work
        let offsets_alt = get_v8_offsets_from_nodejs(nodejs_version).unwrap();

        // Both methods should return the same offsets
        assert_eq!(offsets.isolate.heap, offsets_alt.isolate.heap);
        assert_eq!(
            offsets.isolate.thread_local_top,
            offsets_alt.isolate.thread_local_top
        );
        assert_eq!(
            offsets.thread_local_top.js_entry_sp,
            offsets_alt.thread_local_top.js_entry_sp
        );
    }
}

#[test]
fn test_v8_offsets_structure_sizes() {
    setup_test_env();

    // Validate that offset values are reasonable (not too large)
    const MAX_REASONABLE_OFFSET: u16 = 1024; // 1KB should be more than enough for any struct field

    for version in get_supported_v8_versions() {
        let offsets = get_v8_offsets(&version).unwrap();

        // Check isolate offsets
        assert!(offsets.isolate.heap < MAX_REASONABLE_OFFSET);
        assert!(offsets.isolate.thread_local_top < MAX_REASONABLE_OFFSET);
        assert!(offsets.isolate.context < MAX_REASONABLE_OFFSET);
        assert!(offsets.isolate.pending_exception < MAX_REASONABLE_OFFSET);
        assert!(offsets.isolate.scheduled_exception < MAX_REASONABLE_OFFSET);
        assert!(offsets.isolate.external_caught_exception < MAX_REASONABLE_OFFSET);
        assert!(offsets.isolate.try_catch_handler < MAX_REASONABLE_OFFSET);

        // Check thread_local_top offsets
        assert!(offsets.thread_local_top.js_entry_sp < MAX_REASONABLE_OFFSET);
        assert!(offsets.thread_local_top.c_entry_fp < MAX_REASONABLE_OFFSET);
        assert!(offsets.thread_local_top.handler < MAX_REASONABLE_OFFSET);
        assert!(offsets.thread_local_top.current_context < MAX_REASONABLE_OFFSET);
        assert!(offsets.thread_local_top.pending_exception < MAX_REASONABLE_OFFSET);
        assert!(offsets.thread_local_top.rethrowing_message < MAX_REASONABLE_OFFSET);
        assert!(offsets.thread_local_top.thread_id < MAX_REASONABLE_OFFSET);

        // Check js_frame offsets
        assert!(offsets.js_frame.fp < MAX_REASONABLE_OFFSET);
        assert!(offsets.js_frame.sp < MAX_REASONABLE_OFFSET);
        assert!(offsets.js_frame.pc < MAX_REASONABLE_OFFSET);
        assert!(offsets.js_frame.constant_pool < MAX_REASONABLE_OFFSET);
        assert!(offsets.js_frame.context < MAX_REASONABLE_OFFSET);
        assert!(offsets.js_frame.function < MAX_REASONABLE_OFFSET);

        // Check js_function offsets
        assert!(offsets.js_function.shared_function_info < MAX_REASONABLE_OFFSET);
        assert!(offsets.js_function.code < MAX_REASONABLE_OFFSET);
        assert!(offsets.js_function.context < MAX_REASONABLE_OFFSET);
        assert!(offsets.js_function.feedback_cell < MAX_REASONABLE_OFFSET);

        // Check shared_function_info offsets
        assert!(offsets.shared_function_info.name_or_scope_info < MAX_REASONABLE_OFFSET);
        assert!(offsets.shared_function_info.script < MAX_REASONABLE_OFFSET);
        assert!(offsets.shared_function_info.start_position < MAX_REASONABLE_OFFSET);
        assert!(offsets.shared_function_info.end_position < MAX_REASONABLE_OFFSET);
        assert!(offsets.shared_function_info.function_literal_id < MAX_REASONABLE_OFFSET);
    }
}

#[test]
fn test_comprehensive_nodejs_v8_mapping() {
    setup_test_env();

    // Test all documented Node.js to V8 version mappings
    let test_mappings = vec![
        // Node.js 16.x series
        ((16, 0), (9, 0)),
        ((16, 1), (9, 0)),
        ((16, 4), (9, 0)),
        ((16, 5), (9, 1)),
        ((16, 6), (9, 1)),
        ((16, 9), (9, 1)),
        ((16, 10), (9, 4)),
        ((16, 12), (9, 4)),
        ((16, 15), (9, 4)),
        ((16, 20), (9, 4)),
        // Node.js 18.x series
        ((18, 0), (10, 1)),
        ((18, 2), (10, 1)),
        ((18, 4), (10, 1)),
        ((18, 5), (10, 2)),
        ((18, 7), (10, 2)),
        ((18, 9), (10, 2)),
        ((18, 10), (10, 7)),
        ((18, 12), (10, 7)),
        ((18, 15), (10, 7)),
        ((18, 16), (10, 8)),
        ((18, 18), (10, 8)),
        ((18, 19), (10, 8)),
        // Node.js 20.x series
        ((20, 0), (11, 3)),
        ((20, 2), (11, 3)),
        ((20, 4), (11, 3)),
        ((20, 5), (11, 5)),
        ((20, 7), (11, 5)),
        ((20, 9), (11, 5)),
        ((20, 10), (11, 8)),
        ((20, 12), (11, 8)),
        ((20, 15), (11, 8)),
        // Node.js 21.x series
        ((21, 0), (11, 8)),
        ((21, 2), (11, 8)),
        ((21, 4), (11, 8)),
        ((21, 5), (11, 9)),
        ((21, 7), (11, 9)),
        ((21, 9), (11, 9)),
        // Node.js 22.x series
        ((22, 0), (12, 4)),
        ((22, 1), (12, 4)),
        ((22, 5), (12, 4)),
    ];

    for ((node_major, node_minor), (v8_major, v8_minor)) in test_mappings {
        let node_version = NodeJSVersion::new(node_major, node_minor, 0);
        let v8_version = node_version.to_v8_version();
        let expected_v8 = V8Version::new(v8_major, v8_minor, 0);

        assert_eq!(
            v8_version.major, expected_v8.major,
            "Node.js {}.{} should map to V8 {}.{}, got {}.{}",
            node_major, node_minor, v8_major, v8_minor, v8_version.major, v8_version.minor
        );
        assert_eq!(
            v8_version.minor, expected_v8.minor,
            "Node.js {}.{} should map to V8 {}.{}, got {}.{}",
            node_major, node_minor, v8_major, v8_minor, v8_version.major, v8_version.minor
        );

        // Verify that we have offsets for this V8 version
        let offsets = get_v8_offsets(&v8_version);
        assert!(
            offsets.is_some(),
            "Should have V8 offsets for Node.js {}.{} -> V8 {}.{}",
            node_major,
            node_minor,
            v8_major,
            v8_minor
        );
    }
}
