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

//! Multi-language profiler constants and magic numbers
//!
//! This module contains all magic numbers, constants, and offsets used by the
//! multi-language profiler to eliminate hardcoded values in the codebase.

/// PHP Constants
pub mod php {
    /// PHP API version to major version mapping
    /// These constants are based on official PHP release documentation
    pub const API_VERSION_74: u32 = 20190902;
    pub const API_VERSION_80: u32 = 20200930;
    pub const API_VERSION_81: u32 = 20210902;
    pub const API_VERSION_82: u32 = 20220829;

    /// Zend Engine function types
    /// These values are defined in PHP's zend_compile.h
    pub const ZEND_INTERNAL_FUNCTION: u8 = 1;
    pub const ZEND_USER_FUNCTION: u8 = 2;
    pub const ZEND_OVERLOADED_FUNCTION: u8 = 3;
    pub const ZEND_EVAL_CODE: u8 = 4;

    /// Zend Engine opcode types
    pub const ZEND_NOP: u8 = 0;
    pub const ZEND_ADD: u8 = 1;
    pub const ZEND_SUB: u8 = 2;

    /// PHP frame types for profiling
    pub const PHP_FRAME_USER: u8 = 1;
    pub const PHP_FRAME_INTERNAL: u8 = 2;
    pub const PHP_FRAME_UNKNOWN: u8 = 3;

    /// Memory alignment requirements
    pub const PHP_POINTER_ALIGNMENT: u64 = 8;
    pub const ZEND_STRING_ALIGNMENT: u64 = 8;

    /// Maximum safe string length to read from PHP
    pub const MAX_PHP_STRING_LENGTH: usize = 256;
    pub const MAX_PHP_FUNCTION_NAME_LENGTH: usize = 128;
    pub const MAX_PHP_CLASS_NAME_LENGTH: usize = 128;
    pub const MAX_PHP_FILENAME_LENGTH: usize = 256;

    /// PHP memory layout constants
    pub const EXECUTOR_GLOBALS_SEARCH_RANGE: u64 = 0x100000; // 1MB search range
    pub const PHP_DATA_SEGMENT_MIN_SIZE: u64 = 0x10000; // 64KB minimum

    /// Heuristic offsets for executor_globals detection
    pub const EG_COMMON_OFFSET_1: u64 = 0x1000; // 4KB offset (common)
    pub const EG_COMMON_OFFSET_2: u64 = 0x2000; // 8KB offset (alternative)

    /// PHP version detection patterns
    pub const VERSION_PATTERN_COUNT: usize = 4;
    pub const API_VERSION_PATTERN_COUNT: usize = 1;
}

/// Node.js/V8 Constants
pub mod nodejs {
    /// Node.js to V8 version mapping constants
    /// Based on official Node.js release documentation and V8 changelogs

    /// Node.js 16.x series V8 versions
    pub const NODE_16_0_TO_4_V8_MAJOR: u8 = 9;
    pub const NODE_16_0_TO_4_V8_MINOR: u8 = 0;
    pub const NODE_16_5_TO_9_V8_MINOR: u8 = 1;
    pub const NODE_16_10_TO_15_V8_MINOR: u8 = 4;

    /// Node.js 18.x series V8 versions
    pub const NODE_18_0_TO_4_V8_MAJOR: u8 = 10;
    pub const NODE_18_0_TO_4_V8_MINOR: u8 = 1;
    pub const NODE_18_5_TO_9_V8_MINOR: u8 = 2;
    pub const NODE_18_10_TO_15_V8_MINOR: u8 = 7;
    pub const NODE_18_16_TO_19_V8_MINOR: u8 = 8;

    /// Node.js 20.x series V8 versions
    pub const NODE_20_0_TO_4_V8_MAJOR: u8 = 11;
    pub const NODE_20_0_TO_4_V8_MINOR: u8 = 3;
    pub const NODE_20_5_TO_9_V8_MINOR: u8 = 5;
    pub const NODE_20_10_PLUS_V8_MINOR: u8 = 8;

    /// Node.js 21.x and 22.x series
    pub const NODE_21_V8_MAJOR: u8 = 11;
    pub const NODE_21_0_TO_4_V8_MINOR: u8 = 8;
    pub const NODE_21_5_PLUS_V8_MINOR: u8 = 9;
    pub const NODE_22_V8_MAJOR: u8 = 12;
    pub const NODE_22_V8_MINOR: u8 = 0;

    /// V8 frame type constants
    /// These are derived from V8's frame-constants.h
    pub const V8_FRAME_JAVASCRIPT: u8 = 1;
    pub const V8_FRAME_OPTIMIZED: u8 = 2;
    pub const V8_FRAME_STUB: u8 = 3;
    pub const V8_FRAME_BUILTIN: u8 = 4;
    pub const V8_FRAME_WASM: u8 = 5;
    pub const V8_FRAME_NATIVE: u8 = 6;

    /// V8 object tagging constants
    /// SMI (Small Integer) tag - objects with this tag are immediate values
    pub const V8_SMI_TAG_MASK: u64 = 0x1;
    pub const V8_SMI_TAG_VALUE: u64 = 0x0;

    /// HeapObject tag for pointer validation
    pub const V8_HEAP_OBJECT_TAG: u64 = 0x1;

    /// V8 memory layout constants
    pub const V8_POINTER_ALIGNMENT: u64 = 8;
    pub const V8_OBJECT_ALIGNMENT: u64 = 8;

    /// Maximum safe lengths
    pub const MAX_V8_STRING_LENGTH: usize = 256;
    pub const MAX_JS_FUNCTION_NAME_LENGTH: usize = 128;
    pub const MAX_JS_SCRIPT_NAME_LENGTH: usize = 256;

    /// Isolate detection constants
    pub const ISOLATE_SEARCH_RANGE: u64 = 0x10000000; // 256MB search range
    pub const ISOLATE_BASE_OFFSET: u64 = 0x800000; // 8MB base offset
    pub const HEAP_SEARCH_OFFSET: u64 = 0x100000; // 1MB heap offset

    /// ThreadLocalTop calculation offsets for different V8 versions
    pub const V8_9_TLT_OFFSET: u64 = 0x20; // V8 9.x (Node.js 16.x)
    pub const V8_10_TLT_OFFSET: u64 = 0x28; // V8 10.x (Node.js 18.x)
    pub const V8_11_TLT_OFFSET: u64 = 0x30; // V8 11.x (Node.js 20.x+)

    /// Heuristic base addresses for Isolate detection
    pub const ISOLATE_HEURISTIC_BASE_1: u64 = 0x7fff80000000;
    pub const ISOLATE_HEURISTIC_BASE_2: u64 = 0x7fff90000000;
    pub const ISOLATE_HEURISTIC_BASE_3: u64 = 0x7fffa0000000;

    /// Command line detection patterns
    pub const NODEJS_PATTERN_COUNT: usize = 3;
    pub const VERSION_PATTERN_COUNT: usize = 3;
}

/// General Profiler Constants
pub mod profiler {
    /// Runtime type enumeration
    pub const RUNTIME_TYPE_UNKNOWN: u8 = 0;
    pub const RUNTIME_TYPE_NATIVE: u8 = 1;
    pub const RUNTIME_TYPE_PHP: u8 = 2;
    pub const RUNTIME_TYPE_NODEJS: u8 = 3;
    pub const RUNTIME_TYPE_V8: u8 = 4;
    pub const RUNTIME_TYPE_PYTHON: u8 = 5;

    /// Stack unwinding limits
    pub const MAX_INTERPRETER_STACK_DEPTH: u32 = 64;
    pub const MAX_NODEJS_STACK_DEPTH: u32 = 128;
    pub const MAX_PHP_STACK_DEPTH: u32 = 64;
    pub const MAX_PYTHON_STACK_DEPTH: u32 = 64;

    /// eBPF verifier safe limits
    pub const EBPF_LOOP_LIMIT: u32 = 16; // Maximum unroll limit
    pub const EBPF_SAFE_STACK_LIMIT: u32 = 16; // Conservative stack limit

    /// Error codes
    pub const PROFILER_SUCCESS: i32 = 0;
    pub const PROFILER_ERROR_INVALID_POINTER: i32 = -1;
    pub const PROFILER_ERROR_NO_MEMORY: i32 = -2;
    pub const PROFILER_ERROR_NO_RUNTIME: i32 = -3;
    pub const PROFILER_ERROR_READ_FAILED: i32 = -4;
    pub const PROFILER_ERROR_INVALID_DATA: i32 = -5;

    /// Memory validation constants
    pub const MIN_VALID_USER_ADDRESS: u64 = 0x1000; // 4KB minimum
    pub const MAX_VALID_USER_ADDRESS: u64 = 0x7fffffffffff; // User space limit
    pub const MIN_STACK_ADDRESS: u64 = 0x7fff00000000; // Typical stack start

    /// Cache configuration
    pub const DEFAULT_CACHE_SIZE: usize = 1024;
    pub const DEFAULT_CACHE_TTL_SECONDS: u64 = 300; // 5 minutes
    pub const MAX_CACHE_ENTRIES: usize = 65536; // 64K entries

    /// Performance monitoring
    pub const SAMPLING_RATE_HZ: u32 = 99; // Default sampling rate
    pub const MAX_PROCESSES_TRACKED: u32 = 10000; // Maximum concurrent processes
    pub const UNWINDING_TIMEOUT_US: u64 = 50; // 50 microseconds timeout
}

/// Memory Layout Constants
pub mod memory {
    /// Process memory layout constants for /proc parsing
    pub const PROC_MAPS_BUFFER_SIZE: usize = 4096;
    pub const PROC_CMDLINE_BUFFER_SIZE: usize = 1024;
    pub const PROC_ENVIRON_BUFFER_SIZE: usize = 8192;

    /// ELF binary constants
    pub const ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46]; // "\x7fELF"
    pub const ELF_CLASS_64: u8 = 2; // 64-bit objects
    pub const ELF_DATA_LSB: u8 = 1; // Little endian

    /// Symbol table search constants
    pub const MAX_SYMBOL_NAME_LENGTH: usize = 256;
    pub const MAX_SECTION_NAME_LENGTH: usize = 64;
    pub const SYMBOL_SEARCH_LIMIT: usize = 10000; // Maximum symbols to search
}

/// Documentation for eBPF Constants
///
/// This module provides comprehensive documentation for all magic numbers
/// and constants used in the eBPF profiler implementation.
pub mod documentation {
    //! # eBPF Profiler Constants Documentation
    //!
    //! This document explains the origin and purpose of all magic numbers
    //! used in the multi-language profiler implementation.
    //!
    //! ## PHP Constants
    //!
    //! ### API Version Constants
    //! - `API_VERSION_74` (20190902): PHP 7.4 API version from php-src
    //! - `API_VERSION_80` (20200930): PHP 8.0 API version from php-src
    //! - `API_VERSION_81` (20210902): PHP 8.1 API version from php-src
    //! - `API_VERSION_82` (20220829): PHP 8.2 API version from php-src
    //!
    //! ### Function Type Constants
    //! Derived from `Zend/zend_compile.h` in PHP source:
    //! - `ZEND_INTERNAL_FUNCTION` (1): Built-in PHP functions
    //! - `ZEND_USER_FUNCTION` (2): User-defined PHP functions
    //! - `ZEND_OVERLOADED_FUNCTION` (3): Overloaded functions
    //! - `ZEND_EVAL_CODE` (4): Code from eval()
    //!
    //! ## Node.js/V8 Constants
    //!
    //! ### Version Mapping
    //! Node.js to V8 version mapping is based on:
    //! - Official Node.js release schedule
    //! - V8 engine version used in each Node.js release
    //! - Backward compatibility requirements
    //!
    //! ### Frame Type Constants
    //! V8 frame types derived from `src/execution/frame-constants.h`:
    //! - `V8_FRAME_JAVASCRIPT` (1): Regular JavaScript frames
    //! - `V8_FRAME_OPTIMIZED` (2): Optimized JavaScript frames
    //! - `V8_FRAME_STUB` (3): Code stub frames
    //! - `V8_FRAME_BUILTIN` (4): Built-in function frames
    //!
    //! ## Memory Layout Constants
    //!
    //! ### Address Validation
    //! - `MIN_VALID_USER_ADDRESS` (0x1000): Prevents null pointer access
    //! - `MAX_VALID_USER_ADDRESS` (0x7fffffffffff): User space boundary on x86_64
    //! - `V8_POINTER_ALIGNMENT` (8): Required alignment for V8 objects
    //!
    //! ### Performance Limits
    //! - `EBPF_LOOP_LIMIT` (16): eBPF verifier unroll limit
    //! - `MAX_INTERPRETER_STACK_DEPTH` (64): Reasonable stack depth limit
    //! - `UNWINDING_TIMEOUT_US` (50): Maximum time for stack unwinding
    //!
    //! ## Sources and References
    //!
    //! 1. PHP Source Code: https://github.com/php/php-src
    //! 2. V8 Source Code: https://chromium.googlesource.com/v8/v8
    //! 3. Node.js Release Schedule: https://nodejs.org/en/about/releases/
    //! 4. eBPF Documentation: https://www.kernel.org/doc/html/latest/bpf/
    //! 5. Linux Kernel Source: https://git.kernel.org/
}

/// Runtime Constants Validation
///
/// Helper functions to validate that constants are within expected ranges
/// and maintain consistency across the codebase.
pub mod validation {
    use super::*;

    /// Validate PHP constants are within expected ranges
    pub const fn validate_php_constants() -> bool {
        // API versions should be in chronological order
        php::API_VERSION_74 < php::API_VERSION_80 &&
        php::API_VERSION_80 < php::API_VERSION_81 &&
        php::API_VERSION_81 < php::API_VERSION_82 &&

        // Function types should be valid
        php::ZEND_INTERNAL_FUNCTION > 0 &&
        php::ZEND_USER_FUNCTION > php::ZEND_INTERNAL_FUNCTION &&

        // String lengths should be reasonable
        php::MAX_PHP_STRING_LENGTH <= 1024 &&
        php::MAX_PHP_FUNCTION_NAME_LENGTH <= php::MAX_PHP_STRING_LENGTH
    }

    /// Validate Node.js constants are within expected ranges
    pub const fn validate_nodejs_constants() -> bool {
        // V8 major versions should progress logically
        nodejs::NODE_16_0_TO_4_V8_MAJOR < nodejs::NODE_18_0_TO_4_V8_MAJOR &&
        nodejs::NODE_18_0_TO_4_V8_MAJOR < nodejs::NODE_20_0_TO_4_V8_MAJOR &&
        nodejs::NODE_20_0_TO_4_V8_MAJOR <= nodejs::NODE_21_V8_MAJOR &&
        nodejs::NODE_21_V8_MAJOR <= nodejs::NODE_22_V8_MAJOR &&

        // Memory constants should be reasonable
        nodejs::ISOLATE_SEARCH_RANGE <= 0x100000000 && // Max 4GB
        nodejs::V8_POINTER_ALIGNMENT > 0 &&
        nodejs::MAX_V8_STRING_LENGTH <= 1024
    }

    /// Validate profiler constants are within expected ranges
    pub const fn validate_profiler_constants() -> bool {
        // Stack depths should be reasonable
        profiler::MAX_INTERPRETER_STACK_DEPTH > 0 &&
        profiler::MAX_INTERPRETER_STACK_DEPTH <= 1024 &&

        // Error codes should be negative
        profiler::PROFILER_ERROR_INVALID_POINTER < 0 &&
        profiler::PROFILER_ERROR_NO_MEMORY < 0 &&

        // Memory addresses should be valid
        profiler::MIN_VALID_USER_ADDRESS > 0 &&
        profiler::MAX_VALID_USER_ADDRESS > profiler::MIN_VALID_USER_ADDRESS
    }

    /// Compile-time validation of all constants
    pub const CONSTANTS_VALID: bool =
        validate_php_constants() && validate_nodejs_constants() && validate_profiler_constants();
}

// Compile-time assertion to ensure constants are valid
const _: () = assert!(validation::CONSTANTS_VALID, "Constants validation failed");
