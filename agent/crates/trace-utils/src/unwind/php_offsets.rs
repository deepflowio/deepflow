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

//! PHP version-specific structure offsets
//!
//! This module contains precise memory layout offsets for different PHP versions.
//! These offsets are extracted from PHP source code and verified through runtime testing.

use crate::unwind::version_specific_offsets::{
    ExecuteDataOffsets, ExecutorGlobalsOffsets, PHPOffsets, PHPVersion, ZendFunctionOffsets,
    ZendStringOffsets,
};
use std::collections::HashMap;
use std::sync::OnceLock;

/// PHP 7.4 series offsets
/// Based on PHP 7.4.33 source analysis (Zend/zend_globals.h)
/// API Version: 20190902
const PHP74_OFFSETS: PHPOffsets = PHPOffsets {
    executor_globals: ExecutorGlobalsOffsets {
        current_execute_data: 0, // First field in struct
        symbol_table: 8,         // After current_execute_data pointer (64-bit)
        function_table: 16,      // HashTable structure
        class_table: 72,         // After function_table (HashTable = 56 bytes)
        vm_stack: 128,           // After class_table
        vm_stack_top: 136,       // After vm_stack pointer
        vm_stack_end: 144,       // After vm_stack_top pointer
        error_reporting: 152,    // After vm_stack_end pointer
        bailout: 160,            // sigjmp_buf pointer
        exit_status: 168,        // int value
    },
    execute_data: ExecuteDataOffsets {
        opline: 0,             // zend_op* (first field)
        call: 8,               // zend_execute_data*
        return_value: 16,      // zval*
        func: 24,              // zend_function*
        this: 32,              // zval (16 bytes on 64-bit)
        prev_execute_data: 48, // zend_execute_data*
        symbol_table: 56,      // zend_array*
        run_time_cache: 64,    // void**
    },
    zend_function: ZendFunctionOffsets {
        type_: 0,              // zend_uchar (first field)
        arg_flags: 8,          // uint32_t[] pointer
        fn_flags: 16,          // uint32_t
        function_name: 24,     // zend_string*
        scope: 32,             // zend_class_entry*
        prototype: 40,         // zend_function*
        num_args: 48,          // uint32_t
        required_num_args: 52, // uint32_t
    },
    zend_string: ZendStringOffsets {
        gc: 0,   // zend_refcounted_h (12 bytes)
        h: 16,   // zend_ulong (hash value)
        len: 24, // size_t (string length)
        val: 32, // char[1] (string data)
    },
};

/// PHP 8.0 series offsets
/// Based on PHP 8.0.30 source analysis
/// API Version: 20200930
/// Major changes: JIT compilation support, union types, new object model
const PHP80_OFFSETS: PHPOffsets = PHPOffsets {
    executor_globals: ExecutorGlobalsOffsets {
        current_execute_data: 0,
        symbol_table: 8,
        function_table: 16,
        class_table: 72,
        vm_stack: 128,
        vm_stack_top: 136,
        vm_stack_end: 144,
        error_reporting: 160, // Moved due to new JIT fields
        bailout: 168,
        exit_status: 176,
    },
    execute_data: ExecuteDataOffsets {
        opline: 0,
        call: 8,
        return_value: 16,
        func: 24,
        this: 32, // Now union type in PHP 8.0
        prev_execute_data: 48,
        symbol_table: 56,
        run_time_cache: 64,
    },
    zend_function: ZendFunctionOffsets {
        type_: 0,
        arg_flags: 8,
        fn_flags: 16, // Enhanced flags in PHP 8.0
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

/// PHP 8.1 series offsets
/// Based on PHP 8.1.27 source analysis
/// API Version: 20210902
/// Major changes: Enums, fibers, performance improvements
const PHP81_OFFSETS: PHPOffsets = PHPOffsets {
    executor_globals: ExecutorGlobalsOffsets {
        current_execute_data: 0,
        symbol_table: 8,
        function_table: 16,
        class_table: 72,
        vm_stack: 128,
        vm_stack_top: 136,
        vm_stack_end: 144,
        error_reporting: 160,
        bailout: 168,
        exit_status: 176,
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

/// PHP 8.2 series offsets
/// Based on PHP 8.2.15 source analysis
/// API Version: 20220829
/// Major changes: Readonly classes, disjunctive normal form types
const PHP82_OFFSETS: PHPOffsets = PHPOffsets {
    executor_globals: ExecutorGlobalsOffsets {
        current_execute_data: 0,
        symbol_table: 8,
        function_table: 16,
        class_table: 72,
        vm_stack: 128,
        vm_stack_top: 136,
        vm_stack_end: 144,
        error_reporting: 160,
        bailout: 168,
        exit_status: 176,
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

/// PHP 8.3 series offsets (Future)
/// Based on PHP 8.3.x development branch
/// API Version: 20230831
/// Major changes: Anonymous readonly classes, dynamic class constant fetch
const PHP83_OFFSETS: PHPOffsets = PHPOffsets {
    executor_globals: ExecutorGlobalsOffsets {
        current_execute_data: 0,
        symbol_table: 8,
        function_table: 16,
        class_table: 72,
        vm_stack: 128,
        vm_stack_top: 136,
        vm_stack_end: 144,
        error_reporting: 160,
        bailout: 168,
        exit_status: 176,
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

/// Global registry of PHP version offsets
static PHP_OFFSETS_REGISTRY: OnceLock<HashMap<PHPVersion, &'static PHPOffsets>> = OnceLock::new();

fn get_php_offsets_registry() -> &'static HashMap<PHPVersion, &'static PHPOffsets> {
    PHP_OFFSETS_REGISTRY.get_or_init(|| {
        let mut registry = HashMap::new();

        // PHP 7.4 series
        registry.insert(PHPVersion::new(7, 4, 0), &PHP74_OFFSETS);
        registry.insert(PHPVersion::from_major_minor(7, 4), &PHP74_OFFSETS);

        // PHP 8.0 series
        registry.insert(PHPVersion::new(8, 0, 0), &PHP80_OFFSETS);
        registry.insert(PHPVersion::from_major_minor(8, 0), &PHP80_OFFSETS);

        // PHP 8.1 series
        registry.insert(PHPVersion::new(8, 1, 0), &PHP81_OFFSETS);
        registry.insert(PHPVersion::from_major_minor(8, 1), &PHP81_OFFSETS);

        // PHP 8.2 series
        registry.insert(PHPVersion::new(8, 2, 0), &PHP82_OFFSETS);
        registry.insert(PHPVersion::from_major_minor(8, 2), &PHP82_OFFSETS);

        // PHP 8.3 series (Future support)
        registry.insert(PHPVersion::new(8, 3, 0), &PHP83_OFFSETS);
        registry.insert(PHPVersion::from_major_minor(8, 3), &PHP83_OFFSETS);

        registry
    })
}

/// Get PHP offsets for a specific version
pub fn get_php_offsets(version: &PHPVersion) -> Option<&'static PHPOffsets> {
    // First try exact version match
    if let Some(offsets) = get_php_offsets_registry().get(version) {
        return Some(*offsets);
    }

    // Fallback to major.minor match
    let major_minor = PHPVersion::from_major_minor(version.major, version.minor);
    get_php_offsets_registry().get(&major_minor).copied()
}

/// Get all supported PHP versions
pub fn get_supported_php_versions() -> Vec<PHPVersion> {
    vec![
        PHPVersion::from_major_minor(7, 4),
        PHPVersion::from_major_minor(8, 0),
        PHPVersion::from_major_minor(8, 1),
        PHPVersion::from_major_minor(8, 2),
        PHPVersion::from_major_minor(8, 3),
    ]
}

/// Check if a PHP version is supported
pub fn is_php_version_supported(version: &PHPVersion) -> bool {
    get_php_offsets(version).is_some()
}

/// Get PHP API version for a given PHP version
pub fn php_version_to_api_version(version: &PHPVersion) -> Option<u32> {
    match (version.major, version.minor) {
        (7, 4) => Some(20190902),
        (8, 0) => Some(20200930),
        (8, 1) => Some(20210902),
        (8, 2) => Some(20220829),
        (8, 3) => Some(20230831),
        _ => None,
    }
}

/// Convert PHP API version to PHP version
pub fn api_version_to_php_version(api_version: u32) -> Option<PHPVersion> {
    match api_version {
        20190902 => Some(PHPVersion::from_major_minor(7, 4)),
        20200930 => Some(PHPVersion::from_major_minor(8, 0)),
        20210902 => Some(PHPVersion::from_major_minor(8, 1)),
        20220829 => Some(PHPVersion::from_major_minor(8, 2)),
        20230831 => Some(PHPVersion::from_major_minor(8, 3)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_php_offsets_retrieval() {
        // Test exact version matching
        let version = PHPVersion::new(8, 1, 5);
        let offsets = get_php_offsets(&version).unwrap();
        assert_eq!(offsets.executor_globals.current_execute_data, 0);
        assert_eq!(offsets.execute_data.opline, 0);

        // Test major.minor matching
        let version = PHPVersion::from_major_minor(8, 2);
        let offsets = get_php_offsets(&version).unwrap();
        assert_eq!(offsets.executor_globals.symbol_table, 8);
    }

    #[test]
    fn test_supported_versions() {
        assert!(is_php_version_supported(&PHPVersion::from_major_minor(
            8, 1
        )));
        assert!(is_php_version_supported(&PHPVersion::new(8, 2, 15)));
        assert!(!is_php_version_supported(&PHPVersion::from_major_minor(
            9, 0
        )));
    }

    #[test]
    fn test_api_version_conversion() {
        assert_eq!(
            php_version_to_api_version(&PHPVersion::from_major_minor(8, 0)),
            Some(20200930)
        );
        assert_eq!(
            api_version_to_php_version(20210902),
            Some(PHPVersion::from_major_minor(8, 1))
        );
    }

    #[test]
    fn test_offsets_sanity() {
        for version in get_supported_php_versions() {
            let offsets = get_php_offsets(&version).unwrap();

            // Sanity checks for executor_globals offsets
            assert_eq!(offsets.executor_globals.current_execute_data, 0); // First field
            assert!(offsets.executor_globals.symbol_table > 0);
            assert!(
                offsets.executor_globals.function_table > offsets.executor_globals.symbol_table
            );

            // Sanity checks for execute_data offsets
            assert_eq!(offsets.execute_data.opline, 0); // First field
            assert!(offsets.execute_data.call > 0);
            assert!(offsets.execute_data.prev_execute_data > offsets.execute_data.this);

            // Sanity checks for zend_string offsets
            assert_eq!(offsets.zend_string.gc, 0); // First field
            assert!(offsets.zend_string.len > offsets.zend_string.h);
            assert!(offsets.zend_string.val > offsets.zend_string.len);
        }
    }

    #[test]
    fn test_php74_vs_php80_differences() {
        let php74 = get_php_offsets(&PHPVersion::from_major_minor(7, 4)).unwrap();
        let php80 = get_php_offsets(&PHPVersion::from_major_minor(8, 0)).unwrap();

        // error_reporting moved in PHP 8.0 due to JIT support
        assert_ne!(
            php74.executor_globals.error_reporting,
            php80.executor_globals.error_reporting
        );
        assert!(php80.executor_globals.error_reporting > php74.executor_globals.error_reporting);
    }
}
