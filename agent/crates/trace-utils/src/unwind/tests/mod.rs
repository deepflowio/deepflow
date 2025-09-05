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

//! Comprehensive test suite for version-specific offset system
//!
//! This module contains tests for all components of the new version-specific
//! offset system, ensuring correctness and compatibility.

pub mod memory_optimization_tests;
pub mod php_offsets_tests;
pub mod v8_offsets_tests;
pub mod version_compatibility_tests;
pub mod version_specific_offsets_tests;

use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize test environment
pub fn setup_test_env() {
    INIT.call_once(|| {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .init();
    });
}

/// Common test utilities
pub mod test_utils {
    use crate::unwind::version_specific_offsets::*;

    /// Create a test PHPVersion
    pub fn create_test_php_version(major: u8, minor: u8) -> PHPVersion {
        PHPVersion::from_major_minor(major, minor)
    }

    /// Create a test NodeJSVersion
    pub fn create_test_nodejs_version(major: u8, minor: u8) -> NodeJSVersion {
        NodeJSVersion::from_major_minor(major, minor)
    }

    /// Create a test V8Version
    pub fn create_test_v8_version(major: u8, minor: u8) -> V8Version {
        V8Version::from_major_minor(major, minor)
    }

    /// Mock process for testing
    pub fn create_mock_process() -> u32 {
        std::process::id()
    }

    /// Validate PHPOffsets structure sanity
    pub fn validate_php_offsets(offsets: &PHPOffsets) -> bool {
        // Basic sanity checks
        offsets.executor_globals.current_execute_data == 0 && // First field
        offsets.executor_globals.symbol_table > 0 &&
        offsets.execute_data.opline == 0 && // First field
        offsets.zend_string.gc == 0 // First field
    }

    /// Validate V8Offsets structure sanity  
    pub fn validate_v8_offsets(offsets: &V8Offsets) -> bool {
        // Basic sanity checks
        offsets.isolate.heap == 8 && // After vtable
        offsets.thread_local_top.js_entry_sp == 0 && // First field
        offsets.js_frame.fp == 0 // First field
    }
}
