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

//! Version-specific offsets for multi-language profiling
//!
//! This module provides precise, version-specific memory layout offsets for
//! PHP, Node.js/V8, and other runtime environments. This replaces heuristic
//! memory searches with exact structural knowledge.

use std::fmt;

/// PHP version identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PHPVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl PHPVersion {
    pub fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Create version from major.minor, defaulting patch to 0
    pub fn from_major_minor(major: u8, minor: u8) -> Self {
        Self::new(major, minor, 0)
    }
}

impl fmt::Display for PHPVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// V8 JavaScript engine version identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct V8Version {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl V8Version {
    pub fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Create version from major.minor, defaulting patch to 0
    pub fn from_major_minor(major: u8, minor: u8) -> Self {
        Self::new(major, minor, 0)
    }
}

impl fmt::Display for V8Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Node.js version identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeJSVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl NodeJSVersion {
    pub fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn from_major_minor(major: u8, minor: u8) -> Self {
        Self::new(major, minor, 0)
    }

    /// Convert Node.js version to corresponding V8 version
    pub fn to_v8_version(&self) -> V8Version {
        match (self.major, self.minor) {
            // Node.js 16.x -> V8 9.x
            (16, 0..=4) => V8Version::new(9, 0, 0),
            (16, 5..=9) => V8Version::new(9, 1, 0),
            (16, 10..=15) => V8Version::new(9, 4, 0),
            (16, _) => V8Version::new(9, 4, 0),

            // Node.js 18.x -> V8 10.x
            (18, 0..=4) => V8Version::new(10, 1, 0),
            (18, 5..=9) => V8Version::new(10, 2, 0),
            (18, 10..=15) => V8Version::new(10, 7, 0),
            (18, 16..=19) => V8Version::new(10, 8, 0),
            (18, _) => V8Version::new(10, 8, 0),

            // Node.js 20.x -> V8 11.x
            (20, 0..=4) => V8Version::new(11, 3, 0),
            (20, 5..=9) => V8Version::new(11, 5, 0),
            (20, 10..=15) => V8Version::new(11, 8, 0),
            (20, _) => V8Version::new(11, 8, 0),

            // Node.js 21.x -> V8 11.x
            (21, 0..=4) => V8Version::new(11, 8, 0),
            (21, 5..=9) => V8Version::new(11, 9, 0),
            (21, _) => V8Version::new(11, 9, 0),

            // Node.js 22.x -> V8 12.x
            (22, _) => V8Version::new(12, 4, 0),

            // Fallback for unknown versions
            (major, _) if major >= 22 => V8Version::new(12, 4, 0),
            (major, _) if major >= 20 => V8Version::new(11, 8, 0),
            (major, _) if major >= 18 => V8Version::new(10, 8, 0),
            (major, _) if major >= 16 => V8Version::new(9, 4, 0),
            _ => V8Version::new(9, 0, 0), // Very old versions
        }
    }
}

impl fmt::Display for NodeJSVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// PHP Zend Engine executor_globals structure offsets
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecutorGlobalsOffsets {
    /// Offset to current_execute_data (zend_execute_data*)
    pub current_execute_data: u16,

    /// Offset to symbol_table (zend_array*)
    pub symbol_table: u16,

    /// Offset to function_table (HashTable)
    pub function_table: u16,

    /// Offset to class_table (HashTable)
    pub class_table: u16,

    /// Offset to vm_stack (zend_vm_stack)
    pub vm_stack: u16,

    /// Offset to vm_stack_top (zval*)
    pub vm_stack_top: u16,

    /// Offset to vm_stack_end (zval*)
    pub vm_stack_end: u16,

    /// Offset to error_reporting (int)
    pub error_reporting: u16,

    /// Offset to bailout (sigjmp_buf*)
    pub bailout: u16,

    /// Offset to exit_status (int)
    pub exit_status: u16,
}

/// PHP zend_execute_data structure offsets
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecuteDataOffsets {
    /// Offset to opline (zend_op*)
    pub opline: u16,

    /// Offset to call (zend_execute_data*)
    pub call: u16,

    /// Offset to return_value (zval*)
    pub return_value: u16,

    /// Offset to func (zend_function*)
    pub func: u16,

    /// Offset to This (zval)
    pub this: u16,

    /// Offset to prev_execute_data (zend_execute_data*)
    pub prev_execute_data: u16,

    /// Offset to symbol_table (zend_array*)
    pub symbol_table: u16,

    /// Offset to run_time_cache (void**)
    pub run_time_cache: u16,
}

/// PHP zend_function structure offsets
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ZendFunctionOffsets {
    /// Offset to type (zend_uchar)
    pub type_: u16,

    /// Offset to arg_flags (uint32_t[])
    pub arg_flags: u16,

    /// Offset to fn_flags (uint32_t)
    pub fn_flags: u16,

    /// Offset to function_name (zend_string*)
    pub function_name: u16,

    /// Offset to scope (zend_class_entry*)
    pub scope: u16,

    /// Offset to prototype (zend_function*)
    pub prototype: u16,

    /// Offset to num_args (uint32_t)
    pub num_args: u16,

    /// Offset to required_num_args (uint32_t)
    pub required_num_args: u16,
}

/// PHP zend_string structure offsets
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ZendStringOffsets {
    /// Offset to gc (zend_refcounted_h)
    pub gc: u16,

    /// Offset to h (zend_ulong) - hash value
    pub h: u16,

    /// Offset to len (size_t) - string length
    pub len: u16,

    /// Offset to val (char[1]) - string data
    pub val: u16,
}

/// Complete PHP version-specific offsets
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PHPOffsets {
    pub executor_globals: ExecutorGlobalsOffsets,
    pub execute_data: ExecuteDataOffsets,
    pub zend_function: ZendFunctionOffsets,
    pub zend_string: ZendStringOffsets,
}

/// V8 Isolate structure offsets
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IsolateOffsets {
    /// Offset to heap_ (Heap*)
    pub heap: u16,

    /// Offset to thread_local_top_ (ThreadLocalTop)
    pub thread_local_top: u16,

    /// Offset to context_ (Context)
    pub context: u16,

    /// Offset to pending_exception_ (Object)
    pub pending_exception: u16,

    /// Offset to scheduled_exception_ (Object)
    pub scheduled_exception: u16,

    /// Offset to external_caught_exception_ (bool)
    pub external_caught_exception: u16,

    /// Offset to try_catch_handler_ (v8::TryCatch*)
    pub try_catch_handler: u16,
}

/// V8 ThreadLocalTop structure offsets
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreadLocalTopOffsets {
    /// Offset to js_entry_sp_ (Address)
    pub js_entry_sp: u16,

    /// Offset to c_entry_fp_ (Address)
    pub c_entry_fp: u16,

    /// Offset to handler_ (Address)
    pub handler: u16,

    /// Offset to current_context_ (Context)
    pub current_context: u16,

    /// Offset to pending_exception_ (Object)
    pub pending_exception: u16,

    /// Offset to rethrowing_message_ (bool)
    pub rethrowing_message: u16,

    /// Offset to thread_id_ (ThreadId)
    pub thread_id: u16,
}

/// V8 JavaScript frame offsets
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct JSFrameOffsets {
    /// Offset to fp_ (Address) - frame pointer
    pub fp: u16,

    /// Offset to sp_ (Address) - stack pointer
    pub sp: u16,

    /// Offset to pc_ (Address) - program counter
    pub pc: u16,

    /// Offset to constant_pool_ (FixedArray)
    pub constant_pool: u16,

    /// Offset to context_ (Context)
    pub context: u16,

    /// Offset to function_ (JSFunction)
    pub function: u16,
}

/// V8 JSFunction structure offsets
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct JSFunctionOffsets {
    /// Offset to shared_function_info_ (SharedFunctionInfo)
    pub shared_function_info: u16,

    /// Offset to code_ (Code)
    pub code: u16,

    /// Offset to context_ (Context)
    pub context: u16,

    /// Offset to feedback_cell_ (FeedbackCell)
    pub feedback_cell: u16,
}

/// V8 SharedFunctionInfo structure offsets
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SharedFunctionInfoOffsets {
    /// Offset to name_or_scope_info_ (Object)
    pub name_or_scope_info: u16,

    /// Offset to script_ (Script)
    pub script: u16,

    /// Offset to start_position_ (int)
    pub start_position: u16,

    /// Offset to end_position_ (int)
    pub end_position: u16,

    /// Offset to function_literal_id_ (int)
    pub function_literal_id: u16,
}

/// Complete V8 version-specific offsets
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct V8Offsets {
    pub isolate: IsolateOffsets,
    pub thread_local_top: ThreadLocalTopOffsets,
    pub js_frame: JSFrameOffsets,
    pub js_function: JSFunctionOffsets,
    pub shared_function_info: SharedFunctionInfoOffsets,
}

/// Runtime information for PHP processes
#[derive(Debug, Clone)]
pub struct PHPRuntimeInfo {
    pub version: PHPVersion,
    pub executor_globals_address: u64,
    pub offsets: &'static PHPOffsets,
}

/// Runtime information for Node.js processes
#[derive(Debug, Clone)]
pub struct NodeJSRuntimeInfo {
    pub node_version: NodeJSVersion,
    pub v8_version: V8Version,
    pub isolate_address: u64,
    pub offsets: &'static V8Offsets,
}

/// Errors related to version-specific offset management
#[derive(Debug, thiserror::Error)]
pub enum VersionOffsetError {
    #[error("Unsupported PHP version: {0}")]
    UnsupportedPHPVersion(PHPVersion),

    #[error("Unsupported V8 version: {0}")]
    UnsupportedV8Version(V8Version),

    #[error("Unsupported Node.js version: {0}")]
    UnsupportedNodeJSVersion(NodeJSVersion),

    #[error("Failed to detect runtime version for process {0}")]
    VersionDetectionFailed(u32),

    #[error("Invalid offset validation for process {0}: {1}")]
    InvalidOffsetValidation(u32, String),

    #[error("Memory access error: {0}")]
    MemoryAccessError(String),
}

pub type Result<T> = std::result::Result<T, VersionOffsetError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_display() {
        let php_version = PHPVersion::new(8, 2, 5);
        assert_eq!(php_version.to_string(), "8.2.5");

        let v8_version = V8Version::new(11, 8, 0);
        assert_eq!(v8_version.to_string(), "11.8.0");

        let node_version = NodeJSVersion::new(20, 10, 0);
        assert_eq!(node_version.to_string(), "20.10.0");
    }

    #[test]
    fn test_nodejs_to_v8_version_mapping() {
        // Test Node.js 16 series
        assert_eq!(
            NodeJSVersion::new(16, 0, 0).to_v8_version(),
            V8Version::new(9, 0, 0)
        );
        assert_eq!(
            NodeJSVersion::new(16, 6, 0).to_v8_version(),
            V8Version::new(9, 1, 0)
        );
        assert_eq!(
            NodeJSVersion::new(16, 15, 0).to_v8_version(),
            V8Version::new(9, 4, 0)
        );

        // Test Node.js 18 series
        assert_eq!(
            NodeJSVersion::new(18, 2, 0).to_v8_version(),
            V8Version::new(10, 1, 0)
        );
        assert_eq!(
            NodeJSVersion::new(18, 7, 0).to_v8_version(),
            V8Version::new(10, 2, 0)
        );
        assert_eq!(
            NodeJSVersion::new(18, 17, 0).to_v8_version(),
            V8Version::new(10, 8, 0)
        );

        // Test Node.js 20 series
        assert_eq!(
            NodeJSVersion::new(20, 2, 0).to_v8_version(),
            V8Version::new(11, 3, 0)
        );
        assert_eq!(
            NodeJSVersion::new(20, 8, 0).to_v8_version(),
            V8Version::new(11, 5, 0)
        );
        assert_eq!(
            NodeJSVersion::new(20, 12, 0).to_v8_version(),
            V8Version::new(11, 8, 0)
        );

        // Test Node.js 21 and 22 series
        assert_eq!(
            NodeJSVersion::new(21, 3, 0).to_v8_version(),
            V8Version::new(11, 8, 0)
        );
        assert_eq!(
            NodeJSVersion::new(21, 7, 0).to_v8_version(),
            V8Version::new(11, 9, 0)
        );
        assert_eq!(
            NodeJSVersion::new(22, 0, 0).to_v8_version(),
            V8Version::new(12, 4, 0)
        );
    }

    #[test]
    fn test_version_equality_and_hashing() {
        let v1 = PHPVersion::new(8, 1, 0);
        let v2 = PHPVersion::from_major_minor(8, 1);
        assert_eq!(v1, v2);

        let mut map = std::collections::HashMap::new();
        map.insert(v1, "test");
        assert!(map.contains_key(&v2));
    }
}
