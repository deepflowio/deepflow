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

//! Runtime detection and validation for multi-language profiling
//!
//! This module provides comprehensive runtime detection, memory access,
//! and offset validation functionality for PHP and Node.js processes.

use crate::maps::get_memory_mappings;
use crate::unwind::php_offsets::api_version_to_php_version;
use crate::unwind::version_specific_offsets::*;

use libc::{c_void, iovec, process_vm_readv};
use log::{debug, trace};
use object::{Object, ObjectSymbol};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::sync::OnceLock;

/// Runtime detector with comprehensive validation capabilities
pub struct RuntimeDetector {
    // Symbol cache to avoid repeated symbol table parsing
    symbol_cache: HashMap<u32, HashMap<String, u64>>,
}

impl RuntimeDetector {
    pub fn new() -> Self {
        Self {
            symbol_cache: HashMap::new(),
        }
    }

    /// Clear cached data for a process
    pub fn clear_process_cache(&mut self, pid: u32) {
        self.symbol_cache.remove(&pid);
    }
}

/// Memory access implementation
impl RuntimeDetector {
    /// Read a 64-bit value from process memory
    pub fn read_process_memory_u64(&self, pid: u32, addr: u64) -> Result<u64> {
        let mut buffer = [0u8; 8];
        self.read_process_memory(pid, addr, &mut buffer)?;
        Ok(u64::from_le_bytes(buffer))
    }

    /// Read a 32-bit value from process memory
    pub fn read_process_memory_u32(&self, pid: u32, addr: u64) -> Result<u32> {
        let mut buffer = [0u8; 4];
        self.read_process_memory(pid, addr, &mut buffer)?;
        Ok(u32::from_le_bytes(buffer))
    }

    /// Read arbitrary data from process memory
    pub fn read_process_memory(&self, pid: u32, addr: u64, buffer: &mut [u8]) -> Result<()> {
        let local_iov = iovec {
            iov_base: buffer.as_mut_ptr() as *mut c_void,
            iov_len: buffer.len(),
        };

        let remote_iov = iovec {
            iov_base: addr as *mut c_void,
            iov_len: buffer.len(),
        };

        let result = unsafe { process_vm_readv(pid as i32, &local_iov, 1, &remote_iov, 1, 0) };

        if result == buffer.len() as isize {
            Ok(())
        } else {
            Err(VersionOffsetError::MemoryAccessError(format!(
                "Failed to read {} bytes from address 0x{:x} in process {}: {}",
                buffer.len(),
                addr,
                pid,
                io::Error::last_os_error()
            )))
        }
    }

    /// Read a null-terminated string from process memory
    pub fn read_process_string(&self, pid: u32, addr: u64, max_len: usize) -> Result<String> {
        let mut buffer = vec![0u8; max_len];
        self.read_process_memory(pid, addr, &mut buffer)?;

        // Find null terminator
        let null_pos = buffer.iter().position(|&b| b == 0).unwrap_or(max_len);
        buffer.truncate(null_pos);

        String::from_utf8(buffer)
            .map_err(|e| VersionOffsetError::MemoryAccessError(format!("Invalid UTF-8: {}", e)))
    }

    /// Check if an address is in valid user space range
    pub fn is_valid_user_address(&self, addr: u64) -> bool {
        const MIN_USER_ADDR: u64 = 0x1000; // 4KB minimum
        const MAX_USER_ADDR: u64 = 0x7fffffffffff; // User space limit on x86_64
        const KERNEL_ADDR_START: u64 = 0xffff800000000000; // Kernel space start

        addr >= MIN_USER_ADDR && addr < KERNEL_ADDR_START && addr <= MAX_USER_ADDR
    }

    /// Check if an address range is accessible
    pub fn is_address_range_accessible(&self, pid: u32, start_addr: u64, size: usize) -> bool {
        // Check if the range is in valid user space
        if !self.is_valid_user_address(start_addr)
            || !self.is_valid_user_address(start_addr + size as u64 - 1)
        {
            return false;
        }

        // Try a small read to test accessibility
        let mut test_buffer = [0u8; 8];
        let test_size = std::cmp::min(size, 8);
        self.read_process_memory(pid, start_addr, &mut test_buffer[..test_size])
            .is_ok()
    }
}

/// Symbol resolution implementation
impl RuntimeDetector {
    /// Find symbol address in process memory
    pub fn find_symbol_address(&mut self, pid: u32, symbol_name: &str) -> Result<Option<u64>> {
        // Check cache first
        if let Some(symbols) = self.symbol_cache.get(&pid) {
            if let Some(&addr) = symbols.get(symbol_name) {
                return Ok(Some(addr));
            }
        }

        // Load symbols if not cached
        self.load_process_symbols(pid)?;

        // Check cache again after loading
        if let Some(symbols) = self.symbol_cache.get(&pid) {
            if let Some(&addr) = symbols.get(symbol_name) {
                return Ok(Some(addr));
            }
        }

        Ok(None)
    }

    /// Load symbols from process memory maps
    fn load_process_symbols(&mut self, pid: u32) -> Result<()> {
        let memory_areas = get_memory_mappings(pid).map_err(|e| {
            VersionOffsetError::MemoryAccessError(format!("Failed to get memory mappings: {}", e))
        })?;

        let mut all_symbols = HashMap::new();

        for area in memory_areas.iter() {
            if area.path.starts_with('/')
                && (area.path.contains("php") || area.path.contains("node"))
            {
                if let Ok(symbols) = self.extract_symbols_from_file(&area.path, area.m_start) {
                    all_symbols.extend(symbols);
                }
            }
        }

        self.symbol_cache.insert(pid, all_symbols);
        Ok(())
    }

    /// Extract symbols from an ELF file
    fn extract_symbols_from_file(
        &self,
        file_path: &str,
        base_addr: u64,
    ) -> Result<HashMap<String, u64>> {
        let file_data = fs::read(file_path).map_err(|e| {
            VersionOffsetError::MemoryAccessError(format!(
                "Failed to read file {}: {}",
                file_path, e
            ))
        })?;

        let obj_file = object::File::parse(&*file_data).map_err(|e| {
            VersionOffsetError::MemoryAccessError(format!("Failed to parse ELF file: {}", e))
        })?;

        let mut symbols = HashMap::new();

        // Process regular symbols
        for symbol in obj_file.symbols() {
            if let Ok(name) = symbol.name() {
                if !name.is_empty() && symbol.address() > 0 {
                    symbols.insert(name.to_string(), base_addr + symbol.address());
                }
            }
        }

        // Process dynamic symbols
        for symbol in obj_file.dynamic_symbols() {
            if let Ok(name) = symbol.name() {
                if !name.is_empty() && symbol.address() > 0 {
                    symbols.insert(name.to_string(), base_addr + symbol.address());
                }
            }
        }

        Ok(symbols)
    }
}

/// PHP-specific detection implementation
impl RuntimeDetector {
    /// Detect if a process is PHP and get version
    pub fn detect_php_process(&mut self, pid: u32) -> Result<Option<PHPVersion>> {
        // Check if process looks like PHP
        if !self.is_php_process(pid)? {
            return Ok(None);
        }

        // Try multiple version detection methods
        self.detect_php_version_comprehensive(pid)
    }

    /// Check if process appears to be PHP
    fn is_php_process(&mut self, pid: u32) -> Result<bool> {
        // Method 1: Check executable name
        let exe_path = format!("/proc/{}/exe", pid);
        if let Ok(exe_target) = fs::read_link(&exe_path) {
            let exe_name = exe_target
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            static PHP_BINARY_PATTERNS: &[&str] = &["php", "php-fpm", "php-cgi"];

            for pattern in PHP_BINARY_PATTERNS {
                if exe_name.contains(pattern) {
                    return Ok(true);
                }
            }
        }

        // Method 2: Check for PHP-specific symbols
        static PHP_SYMBOLS: &[&str] = &[
            "executor_globals",
            "zend_execute_ex",
            "php_request_startup",
            "zend_hash_find",
        ];

        for symbol in PHP_SYMBOLS {
            if self.find_symbol_address(pid, symbol)?.is_some() {
                return Ok(true);
            }
        }

        // Method 3: Check memory mappings for PHP libraries
        let memory_areas = get_memory_mappings(pid)
            .map_err(|e| VersionOffsetError::MemoryAccessError(e.to_string()))?;

        for area in memory_areas.iter() {
            if area.path.contains("libphp") || area.path.contains("php.so") {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Comprehensive PHP version detection
    fn detect_php_version_comprehensive(&mut self, pid: u32) -> Result<Option<PHPVersion>> {
        // Method 1: API version from memory
        if let Some(version) = self.detect_php_version_from_api_memory(pid)? {
            return Ok(Some(version));
        }

        // Method 2: Version from symbols
        if let Some(version) = self.detect_php_version_from_symbol_names(pid)? {
            return Ok(Some(version));
        }

        // Method 3: Version from binary path
        if let Some(version) = self.detect_php_version_from_binary_path(pid)? {
            return Ok(Some(version));
        }

        // Method 4: Version from library paths
        if let Some(version) = self.detect_php_version_from_library_paths(pid)? {
            return Ok(Some(version));
        }

        Ok(None)
    }

    fn detect_php_version_from_api_memory(&mut self, pid: u32) -> Result<Option<PHPVersion>> {
        // Look for PHP API version in memory
        static PHP_API_SYMBOLS: &[&str] =
            &["php_api_version", "zend_version_info", "php_version_id"];

        for symbol in PHP_API_SYMBOLS {
            if let Some(addr) = self.find_symbol_address(pid, symbol)? {
                if let Ok(api_version) = self.read_process_memory_u32(pid, addr) {
                    if let Some(version) = api_version_to_php_version(api_version) {
                        return Ok(Some(version));
                    }
                }
            }
        }

        Ok(None)
    }

    fn detect_php_version_from_symbol_names(&mut self, _pid: u32) -> Result<Option<PHPVersion>> {
        // This could analyze symbol names to infer version
        // For now, return None as this requires more sophisticated analysis
        Ok(None)
    }

    fn detect_php_version_from_binary_path(&self, pid: u32) -> Result<Option<PHPVersion>> {
        let exe_path = format!("/proc/{}/exe", pid);
        if let Ok(exe_target) = fs::read_link(&exe_path) {
            let path_str = exe_target.to_string_lossy();

            static PHP_VERSION_REGEX: OnceLock<Regex> = OnceLock::new();
            let regex = PHP_VERSION_REGEX.get_or_init(|| Regex::new(r"php(\d)\.?(\d+)?").unwrap());

            if let Some(caps) = regex.captures(&path_str) {
                let major = caps[1].parse::<u8>().unwrap_or(0);
                let minor = caps
                    .get(2)
                    .map(|m| m.as_str().parse::<u8>().unwrap_or(0))
                    .unwrap_or(0);

                if major > 0 {
                    return Ok(Some(PHPVersion::from_major_minor(major, minor)));
                }
            }
        }

        Ok(None)
    }

    fn detect_php_version_from_library_paths(&self, pid: u32) -> Result<Option<PHPVersion>> {
        let memory_areas = get_memory_mappings(pid)
            .map_err(|e| VersionOffsetError::MemoryAccessError(e.to_string()))?;

        static PHP_LIB_REGEX: OnceLock<Regex> = OnceLock::new();
        let regex = PHP_LIB_REGEX.get_or_init(|| Regex::new(r"libphp(\d)\.?(\d+)?\.so").unwrap());

        for area in memory_areas.iter() {
            if let Some(caps) = regex.captures(&area.path) {
                let major = caps[1].parse::<u8>().unwrap_or(0);
                let minor = caps
                    .get(2)
                    .map(|m| m.as_str().parse::<u8>().unwrap_or(0))
                    .unwrap_or(0);

                if major > 0 {
                    return Ok(Some(PHPVersion::from_major_minor(major, minor)));
                }
            }
        }

        Ok(None)
    }

    /// Find executor_globals address for PHP process
    pub fn find_php_executor_globals(&mut self, pid: u32) -> Result<Option<u64>> {
        // Method 1: Symbol-based lookup (most reliable)
        static EG_SYMBOLS: &[&str] = &[
            "executor_globals",
            "_executor_globals",
            "zend_executor_globals",
        ];

        for symbol in EG_SYMBOLS {
            if let Some(addr) = self.find_symbol_address(pid, symbol)? {
                trace!(
                    "Found executor_globals via symbol '{}' at 0x{:x}",
                    symbol,
                    addr
                );
                return Ok(Some(addr));
            }
        }

        // Method 2: Pattern-based search in data segments
        self.search_executor_globals_pattern(pid)
    }

    fn search_executor_globals_pattern(&self, pid: u32) -> Result<Option<u64>> {
        let memory_areas = get_memory_mappings(pid)
            .map_err(|e| VersionOffsetError::MemoryAccessError(e.to_string()))?;

        // Search in writable data segments
        for area in memory_areas.iter() {
            // Check if this is a writable anonymous mapping (likely contains global variables)
            if area.path.is_empty() {
                // This is a writable anonymous mapping, likely contains global variables
                if let Some(addr) = self.search_executor_globals_in_range(
                    pid,
                    area.m_start,
                    area.m_end - area.m_start,
                )? {
                    return Ok(Some(addr));
                }
            }
        }

        Ok(None)
    }

    fn search_executor_globals_in_range(
        &self,
        pid: u32,
        start_addr: u64,
        size: u64,
    ) -> Result<Option<u64>> {
        const CHUNK_SIZE: usize = 4096; // Read 4KB at a time
        const SEARCH_LIMIT: u64 = 64 * 1024 * 1024; // Limit search to 64MB

        let search_size = std::cmp::min(size, SEARCH_LIMIT);
        let mut offset = 0u64;

        while offset < search_size {
            let current_addr = start_addr + offset;
            let remaining = std::cmp::min(CHUNK_SIZE as u64, search_size - offset) as usize;

            let mut buffer = vec![0u8; remaining];
            if self
                .read_process_memory(pid, current_addr, &mut buffer)
                .is_ok()
            {
                // Look for patterns that suggest executor_globals structure
                if let Some(candidate) = self.find_executor_globals_candidate(&buffer, current_addr)
                {
                    return Ok(Some(candidate));
                }
            }

            offset += remaining as u64;
        }

        Ok(None)
    }

    fn find_executor_globals_candidate(&self, _buffer: &[u8], _base_addr: u64) -> Option<u64> {
        // TODO: Implement pattern matching for executor_globals structure
        // This would look for specific patterns in memory that indicate the presence
        // of executor_globals structure
        None
    }
}

/// Node.js-specific detection implementation
impl RuntimeDetector {
    /// Detect if a process is Node.js and get version
    pub fn detect_nodejs_process(&mut self, pid: u32) -> Result<Option<NodeJSVersion>> {
        if !self.is_nodejs_process(pid)? {
            return Ok(None);
        }

        self.detect_nodejs_version_comprehensive(pid)
    }

    /// Check if process appears to be Node.js
    fn is_nodejs_process(&mut self, pid: u32) -> Result<bool> {
        // Method 1: Check executable name
        let exe_path = format!("/proc/{}/exe", pid);
        if let Ok(exe_target) = fs::read_link(&exe_path) {
            let exe_name = exe_target
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            if exe_name.contains("node") {
                return Ok(true);
            }
        }

        // Method 2: Check for Node.js/V8 specific symbols
        static NODEJS_SYMBOLS: &[&str] = &[
            "v8::Isolate::GetCurrent",
            "node::Environment::GetCurrent",
            "uv_loop_init",
            "_ZN2v87Isolate10GetCurrentEv",
        ];

        for symbol in NODEJS_SYMBOLS {
            if self.find_symbol_address(pid, symbol)?.is_some() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Comprehensive Node.js version detection
    fn detect_nodejs_version_comprehensive(&mut self, pid: u32) -> Result<Option<NodeJSVersion>> {
        // Method 1: Version from binary path
        if let Some(version) = self.detect_nodejs_version_from_path(pid)? {
            return Ok(Some(version));
        }

        // Method 2: Version from command line
        if let Some(version) = self.detect_nodejs_version_from_cmdline(pid)? {
            return Ok(Some(version));
        }

        // Method 3: Version from memory (if available)
        if let Some(version) = self.detect_nodejs_version_from_memory(pid)? {
            return Ok(Some(version));
        }

        Ok(None)
    }

    fn detect_nodejs_version_from_path(&self, pid: u32) -> Result<Option<NodeJSVersion>> {
        let exe_path = format!("/proc/{}/exe", pid);
        if let Ok(exe_target) = fs::read_link(&exe_path) {
            let path_str = exe_target.to_string_lossy();

            static NODE_VERSION_REGEX: OnceLock<Regex> = OnceLock::new();
            let regex = NODE_VERSION_REGEX
                .get_or_init(|| Regex::new(r"node-?v?(\d+)\.(\d+)\.(\d+)|node(\d+)").unwrap());

            if let Some(caps) = regex.captures(&path_str) {
                if let Some(simple_major) = caps.get(4) {
                    // Simple version like "node16"
                    let major = simple_major.as_str().parse::<u8>().unwrap_or(0);
                    if major > 0 {
                        return Ok(Some(NodeJSVersion::from_major_minor(major, 0)));
                    }
                } else if let (Ok(major), Ok(minor), Ok(patch)) = (
                    caps[1].parse::<u8>(),
                    caps[2].parse::<u8>(),
                    caps[3].parse::<u8>(),
                ) {
                    return Ok(Some(NodeJSVersion::new(major, minor, patch)));
                }
            }
        }

        Ok(None)
    }

    fn detect_nodejs_version_from_cmdline(&self, pid: u32) -> Result<Option<NodeJSVersion>> {
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
            static CMDLINE_VERSION_REGEX: OnceLock<Regex> = OnceLock::new();
            let regex = CMDLINE_VERSION_REGEX.get_or_init(|| Regex::new(r"node(\d+)").unwrap());

            if let Some(caps) = regex.captures(&cmdline) {
                if let Ok(major) = caps[1].parse::<u8>() {
                    return Ok(Some(NodeJSVersion::from_major_minor(major, 0)));
                }
            }
        }

        Ok(None)
    }

    fn detect_nodejs_version_from_memory(&mut self, _pid: u32) -> Result<Option<NodeJSVersion>> {
        // TODO: Implement reading Node.js version from memory
        // This could look for version strings in process memory
        Ok(None)
    }

    /// Find V8 Isolate address for Node.js process
    pub fn find_nodejs_isolate(&mut self, pid: u32) -> Result<Option<u64>> {
        static V8_ISOLATE_SYMBOLS: &[&str] = &[
            "v8::Isolate::GetCurrent",
            "_ZN2v87Isolate10GetCurrentEv", // Mangled name
            "v8::internal::Isolate::Current",
        ];

        for symbol in V8_ISOLATE_SYMBOLS {
            if let Some(addr) = self.find_symbol_address(pid, symbol)? {
                trace!("Found V8 Isolate via symbol '{}' at 0x{:x}", symbol, addr);
                return Ok(Some(addr));
            }
        }

        Ok(None)
    }
}

/// Validation implementation
impl RuntimeDetector {
    /// Validate PHP offsets against runtime memory
    pub fn validate_php_offsets(
        &mut self,
        pid: u32,
        eg_addr: u64,
        offsets: &PHPOffsets,
    ) -> Result<()> {
        // Validate current_execute_data pointer
        let current_execute_data_addr =
            eg_addr + offsets.executor_globals.current_execute_data as u64;
        if let Ok(current_execute_data) =
            self.read_process_memory_u64(pid, current_execute_data_addr)
        {
            if current_execute_data != 0 && !self.is_valid_user_address(current_execute_data) {
                return Err(VersionOffsetError::InvalidOffsetValidation(
                    pid,
                    format!("Invalid current_execute_data: 0x{:x}", current_execute_data),
                ));
            }
        }

        // Validate symbol_table pointer
        let symbol_table_addr = eg_addr + offsets.executor_globals.symbol_table as u64;
        if let Ok(symbol_table) = self.read_process_memory_u64(pid, symbol_table_addr) {
            if symbol_table != 0 && !self.is_valid_user_address(symbol_table) {
                return Err(VersionOffsetError::InvalidOffsetValidation(
                    pid,
                    format!("Invalid symbol_table: 0x{:x}", symbol_table),
                ));
            }
        }

        debug!("PHP offsets validation passed for process {}", pid);
        Ok(())
    }

    /// Validate V8 offsets against runtime memory
    pub fn validate_v8_offsets(
        &mut self,
        pid: u32,
        isolate_addr: u64,
        offsets: &V8Offsets,
    ) -> Result<()> {
        // Validate heap pointer
        let heap_addr = isolate_addr + offsets.isolate.heap as u64;
        if let Ok(heap_ptr) = self.read_process_memory_u64(pid, heap_addr) {
            if heap_ptr != 0 && !self.is_valid_user_address(heap_ptr) {
                return Err(VersionOffsetError::InvalidOffsetValidation(
                    pid,
                    format!("Invalid heap pointer: 0x{:x}", heap_ptr),
                ));
            }
        }

        // Validate thread_local_top
        let tlt_addr = isolate_addr + offsets.isolate.thread_local_top as u64;
        if !self.is_address_range_accessible(pid, tlt_addr, 64) {
            return Err(VersionOffsetError::InvalidOffsetValidation(
                pid,
                format!("ThreadLocalTop not accessible at: 0x{:x}", tlt_addr),
            ));
        }

        debug!("V8 offsets validation passed for process {}", pid);
        Ok(())
    }
}

impl Default for RuntimeDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_validation() {
        let detector = RuntimeDetector::new();

        // Valid user addresses
        assert!(detector.is_valid_user_address(0x1000));
        assert!(detector.is_valid_user_address(0x7fff00000000));

        // Invalid addresses
        assert!(!detector.is_valid_user_address(0x0)); // NULL
        assert!(!detector.is_valid_user_address(0x500)); // Too low
        assert!(!detector.is_valid_user_address(0xffff800000000000)); // Kernel space
    }

    #[test]
    fn test_version_regex_patterns() {
        static PHP_VERSION_REGEX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let regex = PHP_VERSION_REGEX.get_or_init(|| Regex::new(r"php(\d)\.?(\d+)?").unwrap());

        // Test PHP version patterns
        assert!(regex.is_match("php8.1"));
        assert!(regex.is_match("php74"));
        assert!(regex.is_match("/usr/bin/php8.2"));

        static NODE_VERSION_REGEX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let regex = NODE_VERSION_REGEX
            .get_or_init(|| Regex::new(r"node-?v?(\d+)\.(\d+)\.(\d+)|node(\d+)").unwrap());

        // Test Node.js version patterns
        assert!(regex.is_match("node-v18.17.0"));
        assert!(regex.is_match("nodejs18.17.0"));
        assert!(regex.is_match("node20"));
    }
}
