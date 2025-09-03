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

//! Tests for PHP version-specific offsets

use super::setup_test_env;
use super::test_utils::*;
use crate::unwind::php_offsets::*;
use crate::unwind::version_specific_offsets::*;

#[test]
fn test_php_offsets_retrieval() {
    setup_test_env();

    // Test exact version matching
    let version = PHPVersion::new(8, 1, 5);
    let offsets = get_php_offsets(&version).unwrap();

    // Validate basic structure
    assert_eq!(offsets.executor_globals.current_execute_data, 0); // First field
    assert!(offsets.executor_globals.symbol_table > 0);
    assert!(offsets.executor_globals.function_table > offsets.executor_globals.symbol_table);

    assert_eq!(offsets.execute_data.opline, 0); // First field
    assert!(offsets.execute_data.call > 0);
    assert!(offsets.execute_data.prev_execute_data > offsets.execute_data.this);

    assert_eq!(offsets.zend_string.gc, 0); // First field
    assert!(offsets.zend_string.len > offsets.zend_string.h);
    assert!(offsets.zend_string.val > offsets.zend_string.len);

    // Test major.minor matching
    let version_mm = PHPVersion::from_major_minor(8, 2);
    let offsets_mm = get_php_offsets(&version_mm).unwrap();
    assert_eq!(offsets_mm.executor_globals.symbol_table, 8);
}

#[test]
fn test_all_supported_php_versions() {
    setup_test_env();

    let supported_versions = get_supported_php_versions();
    assert!(!supported_versions.is_empty());

    // Expected supported versions
    let expected_versions = vec![
        PHPVersion::from_major_minor(7, 4),
        PHPVersion::from_major_minor(8, 0),
        PHPVersion::from_major_minor(8, 1),
        PHPVersion::from_major_minor(8, 2),
        PHPVersion::from_major_minor(8, 3),
    ];

    for expected in &expected_versions {
        assert!(
            supported_versions.contains(expected),
            "Version {} should be supported",
            expected
        );
        assert!(
            is_php_version_supported(expected),
            "Version {} should be supported",
            expected
        );

        let offsets = get_php_offsets(expected).unwrap();
        assert!(
            validate_php_offsets(offsets),
            "Offsets for {} should be valid",
            expected
        );
    }
}

#[test]
fn test_php_api_version_mapping() {
    setup_test_env();

    // Test PHP version to API version conversion
    let test_cases = vec![
        (PHPVersion::from_major_minor(7, 4), 20190902),
        (PHPVersion::from_major_minor(8, 0), 20200930),
        (PHPVersion::from_major_minor(8, 1), 20210902),
        (PHPVersion::from_major_minor(8, 2), 20220829),
        (PHPVersion::from_major_minor(8, 3), 20230831),
    ];

    for (version, expected_api) in &test_cases {
        let api_version = php_version_to_api_version(version).unwrap();
        assert_eq!(
            api_version, *expected_api,
            "PHP {} should have API version {}, got {}",
            version, expected_api, api_version
        );

        // Test reverse mapping
        let recovered_version = api_version_to_php_version(api_version).unwrap();
        assert_eq!(
            recovered_version, *version,
            "API version {} should map back to PHP {}, got {}",
            api_version, version, recovered_version
        );
    }
}

#[test]
fn test_unsupported_php_versions() {
    setup_test_env();

    let unsupported_versions = vec![
        PHPVersion::from_major_minor(5, 6),  // Too old
        PHPVersion::from_major_minor(7, 0),  // Too old
        PHPVersion::from_major_minor(7, 3),  // Not supported
        PHPVersion::from_major_minor(9, 0),  // Future version
        PHPVersion::from_major_minor(10, 0), // Very future version
    ];

    for version in &unsupported_versions {
        assert!(
            !is_php_version_supported(version),
            "Version {} should not be supported",
            version
        );
        assert!(
            get_php_offsets(version).is_none(),
            "Version {} should return None offsets",
            version
        );
        assert!(
            php_version_to_api_version(version).is_none(),
            "Version {} should return None API version",
            version
        );
    }
}

#[test]
fn test_php_offsets_sanity_checks() {
    setup_test_env();

    for version in get_supported_php_versions() {
        let offsets = get_php_offsets(&version).unwrap();

        // Executor globals sanity checks
        assert_eq!(
            offsets.executor_globals.current_execute_data, 0,
            "current_execute_data should be first field for PHP {}",
            version
        );
        assert!(
            offsets.executor_globals.symbol_table > 0,
            "symbol_table offset should be > 0 for PHP {}",
            version
        );
        assert!(
            offsets.executor_globals.function_table > offsets.executor_globals.symbol_table,
            "function_table should be after symbol_table for PHP {}",
            version
        );
        assert!(
            offsets.executor_globals.class_table > offsets.executor_globals.function_table,
            "class_table should be after function_table for PHP {}",
            version
        );

        // Execute data sanity checks
        assert_eq!(
            offsets.execute_data.opline, 0,
            "opline should be first field for PHP {}",
            version
        );
        assert!(
            offsets.execute_data.call > 0,
            "call offset should be > 0 for PHP {}",
            version
        );
        assert!(
            offsets.execute_data.prev_execute_data > offsets.execute_data.this,
            "prev_execute_data should be after this for PHP {}",
            version
        );

        // Zend function sanity checks
        assert_eq!(
            offsets.zend_function.type_, 0,
            "type should be first field for PHP {}",
            version
        );
        assert!(
            offsets.zend_function.function_name > 0,
            "function_name offset should be > 0 for PHP {}",
            version
        );

        // Zend string sanity checks
        assert_eq!(
            offsets.zend_string.gc, 0,
            "gc should be first field for PHP {}",
            version
        );
        assert!(
            offsets.zend_string.h > 0,
            "h offset should be > 0 for PHP {}",
            version
        );
        assert!(
            offsets.zend_string.len > offsets.zend_string.h,
            "len should be after h for PHP {}",
            version
        );
        assert!(
            offsets.zend_string.val > offsets.zend_string.len,
            "val should be after len for PHP {}",
            version
        );
    }
}

#[test]
fn test_php74_vs_php80_differences() {
    setup_test_env();

    let php74 = get_php_offsets(&PHPVersion::from_major_minor(7, 4)).unwrap();
    let php80 = get_php_offsets(&PHPVersion::from_major_minor(8, 0)).unwrap();

    // PHP 8.0 introduced JIT compilation which moved some fields
    // error_reporting should have moved to a higher offset in PHP 8.0
    assert_ne!(
        php74.executor_globals.error_reporting, php80.executor_globals.error_reporting,
        "error_reporting offset should be different between PHP 7.4 and 8.0"
    );
    assert!(
        php80.executor_globals.error_reporting > php74.executor_globals.error_reporting,
        "PHP 8.0 error_reporting should be at higher offset than PHP 7.4"
    );
}

#[test]
fn test_php_version_progression() {
    setup_test_env();

    let versions = vec![
        PHPVersion::from_major_minor(7, 4),
        PHPVersion::from_major_minor(8, 0),
        PHPVersion::from_major_minor(8, 1),
        PHPVersion::from_major_minor(8, 2),
        PHPVersion::from_major_minor(8, 3),
    ];

    // All versions should be supported
    for version in &versions {
        assert!(
            is_php_version_supported(version),
            "PHP {} should be supported",
            version
        );

        let offsets = get_php_offsets(version).unwrap();
        assert!(
            validate_php_offsets(offsets),
            "PHP {} offsets should be valid",
            version
        );

        // Basic structure should be consistent across versions
        assert_eq!(offsets.executor_globals.current_execute_data, 0);
        assert_eq!(offsets.execute_data.opline, 0);
        assert_eq!(offsets.zend_function.type_, 0);
        assert_eq!(offsets.zend_string.gc, 0);
    }
}

#[test]
fn test_api_version_edge_cases() {
    setup_test_env();

    // Test unknown API versions
    let unknown_api_versions = vec![
        20180101, // Too old
        20190101, // Between versions
        20250101, // Future version
        0,        // Invalid
        u32::MAX, // Invalid
    ];

    for api_version in &unknown_api_versions {
        assert!(
            api_version_to_php_version(*api_version).is_none(),
            "Unknown API version {} should return None",
            api_version
        );
    }
}

#[test]
fn test_php_offsets_structure_sizes() {
    setup_test_env();

    // Validate that offset values are reasonable (not too large)
    const MAX_REASONABLE_OFFSET: u16 = 1024; // 1KB should be more than enough for any struct field

    for version in get_supported_php_versions() {
        let offsets = get_php_offsets(&version).unwrap();

        // Check executor_globals offsets
        assert!(offsets.executor_globals.current_execute_data < MAX_REASONABLE_OFFSET);
        assert!(offsets.executor_globals.symbol_table < MAX_REASONABLE_OFFSET);
        assert!(offsets.executor_globals.function_table < MAX_REASONABLE_OFFSET);
        assert!(offsets.executor_globals.class_table < MAX_REASONABLE_OFFSET);
        assert!(offsets.executor_globals.vm_stack < MAX_REASONABLE_OFFSET);
        assert!(offsets.executor_globals.vm_stack_top < MAX_REASONABLE_OFFSET);
        assert!(offsets.executor_globals.vm_stack_end < MAX_REASONABLE_OFFSET);
        assert!(offsets.executor_globals.error_reporting < MAX_REASONABLE_OFFSET);
        assert!(offsets.executor_globals.bailout < MAX_REASONABLE_OFFSET);
        assert!(offsets.executor_globals.exit_status < MAX_REASONABLE_OFFSET);

        // Check execute_data offsets
        assert!(offsets.execute_data.opline < MAX_REASONABLE_OFFSET);
        assert!(offsets.execute_data.call < MAX_REASONABLE_OFFSET);
        assert!(offsets.execute_data.return_value < MAX_REASONABLE_OFFSET);
        assert!(offsets.execute_data.func < MAX_REASONABLE_OFFSET);
        assert!(offsets.execute_data.this < MAX_REASONABLE_OFFSET);
        assert!(offsets.execute_data.prev_execute_data < MAX_REASONABLE_OFFSET);
        assert!(offsets.execute_data.symbol_table < MAX_REASONABLE_OFFSET);
        assert!(offsets.execute_data.run_time_cache < MAX_REASONABLE_OFFSET);

        // Check zend_function offsets
        assert!(offsets.zend_function.type_ < MAX_REASONABLE_OFFSET);
        assert!(offsets.zend_function.arg_flags < MAX_REASONABLE_OFFSET);
        assert!(offsets.zend_function.fn_flags < MAX_REASONABLE_OFFSET);
        assert!(offsets.zend_function.function_name < MAX_REASONABLE_OFFSET);
        assert!(offsets.zend_function.scope < MAX_REASONABLE_OFFSET);
        assert!(offsets.zend_function.prototype < MAX_REASONABLE_OFFSET);
        assert!(offsets.zend_function.num_args < MAX_REASONABLE_OFFSET);
        assert!(offsets.zend_function.required_num_args < MAX_REASONABLE_OFFSET);

        // Check zend_string offsets
        assert!(offsets.zend_string.gc < MAX_REASONABLE_OFFSET);
        assert!(offsets.zend_string.h < MAX_REASONABLE_OFFSET);
        assert!(offsets.zend_string.len < MAX_REASONABLE_OFFSET);
        assert!(offsets.zend_string.val < MAX_REASONABLE_OFFSET);
    }
}
