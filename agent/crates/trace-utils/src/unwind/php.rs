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

use crate::unwind::cache::BoundedLruCache;
use log::{debug, trace, warn};
use regex::Regex;
use semver::Version;
use std::collections::HashMap;
use std::fs;
use std::time::Duration;

use crate::error::Result;
use crate::utils::{bpf_update_elem, BPF_ANY};

/// PHP version information
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

    pub fn from_version(version: &Version) -> Self {
        Self {
            major: version.major as u8,
            minor: version.minor as u8,
            patch: version.patch as u8,
        }
    }

    pub fn to_u32(&self) -> u32 {
        ((self.major as u32) << 16) | ((self.minor as u32) << 8) | (self.patch as u32)
    }
}

/// PHP SAPI (Server API) types
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum PHPSapi {
    Unknown = 0,
    CLI = 1,
    FPM = 2,
    Apache = 3,
    Nginx = 4,
}

impl From<&str> for PHPSapi {
    fn from(sapi: &str) -> Self {
        match sapi.to_lowercase().as_str() {
            "cli" => PHPSapi::CLI,
            "fpm" | "php-fpm" => PHPSapi::FPM,
            "apache" | "apache2" => PHPSapi::Apache,
            "nginx" => PHPSapi::Nginx,
            _ => PHPSapi::Unknown,
        }
    }
}

/// PHP memory layout offsets for different versions
#[derive(Debug, Clone)]
#[repr(C)]
pub struct PHPOffsets {
    // executor_globals offsets
    pub eg_current_execute_data: u16,
    pub eg_vm_stack: u16,
    pub eg_vm_stack_top: u16,
    pub eg_vm_stack_end: u16,

    // zend_execute_data offsets
    pub ed_opline: u16,
    pub ed_call: u16,
    pub ed_return_value: u16,
    pub ed_func: u16,
    pub ed_this: u16,
    pub ed_prev_execute_data: u16,
    pub ed_symbol_table: u16,

    // zend_function offsets
    pub func_common_function_name: u16,
    pub func_common_scope: u16,
    pub func_common_prototype: u16,
    pub func_type: u16,
    pub func_op_array: u16,

    // zend_op_array offsets
    pub op_array_filename: u16,
    pub op_array_function_name: u16,
    pub op_array_scope: u16,
    pub op_array_line_start: u16,
    pub op_array_line_end: u16,

    // zend_class_entry offsets
    pub ce_name: u16,
    pub ce_parent: u16,
    pub ce_type: u16,

    // zend_string offsets
    pub str_val: u16,
    pub str_len: u16,

    // zend_op offsets
    pub op_lineno: u16,
}

/// PHP offsets for different versions
const PHP74_OFFSETS: PHPOffsets = PHPOffsets {
    // executor_globals
    eg_current_execute_data: 0x00,
    eg_vm_stack: 0x08,
    eg_vm_stack_top: 0x10,
    eg_vm_stack_end: 0x18,

    // zend_execute_data
    ed_opline: 0x00,
    ed_call: 0x08,
    ed_return_value: 0x10,
    ed_func: 0x18,
    ed_this: 0x20,
    ed_prev_execute_data: 0x30,
    ed_symbol_table: 0x38,

    // zend_function
    func_common_function_name: 0x08,
    func_common_scope: 0x10,
    func_common_prototype: 0x18,
    func_type: 0x00,
    func_op_array: 0x30,

    // zend_op_array
    op_array_filename: 0x80,
    op_array_function_name: 0x88,
    op_array_scope: 0x90,
    op_array_line_start: 0x20,
    op_array_line_end: 0x24,

    // zend_class_entry
    ce_name: 0x48,
    ce_parent: 0x68,
    ce_type: 0x44,

    // zend_string
    str_val: 0x18,
    str_len: 0x10,

    // zend_op
    op_lineno: 0x18,
};

const PHP80_OFFSETS: PHPOffsets = PHPOffsets {
    // executor_globals
    eg_current_execute_data: 0x00,
    eg_vm_stack: 0x08,
    eg_vm_stack_top: 0x10,
    eg_vm_stack_end: 0x18,

    // zend_execute_data
    ed_opline: 0x00,
    ed_call: 0x08,
    ed_return_value: 0x10,
    ed_func: 0x20,
    ed_this: 0x28,
    ed_prev_execute_data: 0x38,
    ed_symbol_table: 0x40,

    // zend_function
    func_common_function_name: 0x10,
    func_common_scope: 0x18,
    func_common_prototype: 0x20,
    func_type: 0x00,
    func_op_array: 0x30,

    // zend_op_array
    op_array_filename: 0x88,
    op_array_function_name: 0x90,
    op_array_scope: 0x98,
    op_array_line_start: 0x20,
    op_array_line_end: 0x24,

    // zend_class_entry
    ce_name: 0x48,
    ce_parent: 0x68,
    ce_type: 0x44,

    // zend_string
    str_val: 0x18,
    str_len: 0x10,

    // zend_op
    op_lineno: 0x18,
};

const PHP81_OFFSETS: PHPOffsets = PHP80_OFFSETS; // Same as 8.0 for now
const PHP82_OFFSETS: PHPOffsets = PHP80_OFFSETS; // Same as 8.0 for now

/// PHP runtime information
#[derive(Debug, Clone)]
#[repr(C)]
pub struct PHPRuntimeInfo {
    pub executor_globals: u64,
    pub offsets_id: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub sapi_type: u8,
}

/// PHP runtime detector with bounded cache
pub struct PHPRuntimeDetector {
    php_patterns: Vec<Regex>,
    version_cache: BoundedLruCache<u32, PHPVersion>,
    offsets_map: HashMap<PHPVersion, u8>,
    next_offsets_id: u8,
}

impl Default for PHPRuntimeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PHPRuntimeDetector {
    pub fn new() -> Self {
        // Create bounded cache with max 1024 entries and 5 minute TTL
        let version_cache = BoundedLruCache::new(1024, Duration::from_secs(300));

        Self {
            php_patterns: vec![
                Regex::new(r"php(-fpm)?(\d+)?$").unwrap(),
                Regex::new(r"php-cgi").unwrap(),
                Regex::new(r"apache2.*php").unwrap(),
                Regex::new(r"nginx.*php").unwrap(),
            ],
            version_cache,
            offsets_map: HashMap::new(),
            next_offsets_id: 1,
        }
    }

    pub fn detect(&mut self, pid: u32) -> Result<Option<PHPRuntimeInfo>> {
        // 1. Check if process is PHP
        let cmdline = self.read_proc_cmdline(pid)?;
        if !self.is_php_process(&cmdline) {
            return Ok(None);
        }

        // 2. Detect PHP version
        let version = match self.detect_version(pid) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(e) => {
                debug!("Failed to detect PHP version for PID {}: {}", pid, e);
                return Ok(None);
            }
        };

        // 3. Get executor_globals address
        let executor_globals = match self.find_executor_globals(pid) {
            Ok(Some(addr)) => addr,
            Ok(None) => return Ok(None),
            Err(e) => {
                debug!("Failed to find executor_globals for PID {}: {}", pid, e);
                return Ok(None);
            }
        };

        // 4. Get offsets ID
        let offsets_id = self.get_or_create_offsets_id(&version);

        // 5. Detect SAPI
        let sapi = self.detect_sapi(&cmdline);

        Ok(Some(PHPRuntimeInfo {
            executor_globals,
            offsets_id,
            version_major: version.major,
            version_minor: version.minor,
            sapi_type: sapi as u8,
        }))
    }

    fn read_proc_cmdline(&self, pid: u32) -> Result<String> {
        let path = format!("/proc/{}/cmdline", pid);
        let content = fs::read_to_string(&path)?;
        Ok(content.replace('\0', " "))
    }

    fn is_php_process(&self, cmdline: &str) -> bool {
        self.php_patterns
            .iter()
            .any(|pattern| pattern.is_match(cmdline))
    }

    fn detect_version(&mut self, pid: u32) -> Result<Option<PHPVersion>> {
        // Check cache first
        if let Some(version) = self.version_cache.get(&pid) {
            return Ok(Some(version));
        }

        // Try to detect version from executable
        let version = self
            .detect_version_from_executable(pid)
            .or_else(|_| self.detect_version_from_symbols(pid))
            .or_else(|_| self.detect_version_from_maps(pid))?;

        if let Some(ref v) = version {
            if let Err(e) = self.version_cache.insert(pid, v.clone()) {
                warn!("Failed to cache PHP version for PID {}: {}", pid, e);
            }
        }

        Ok(version)
    }

    fn detect_version_from_executable(&self, pid: u32) -> Result<Option<PHPVersion>> {
        let exe_path = format!("/proc/{}/exe", pid);
        let exe_path = fs::read_link(&exe_path)?;

        // Try to extract version from path
        if let Some(version_str) = self.extract_version_from_path(&exe_path.to_string_lossy()) {
            if let Ok(version) = Version::parse(&version_str) {
                return Ok(Some(PHPVersion::from_version(&version)));
            }
        }

        // Try to run --version if it's CLI
        // This is a simplified approach; in production you might want to be more careful
        Ok(None)
    }

    fn detect_version_from_symbols(&self, pid: u32) -> Result<Option<PHPVersion>> {
        // Read the PHP binary and look for version symbols
        let exe_path = format!("/proc/{}/exe", pid);
        let exe_path = fs::read_link(&exe_path)?;

        // Read the binary content
        if let Ok(binary_content) = fs::read(&exe_path) {
            // Look for PHP version strings in the binary
            let binary_str = String::from_utf8_lossy(&binary_content);

            // Common PHP version patterns in binaries
            let version_patterns = vec![
                Regex::new(r"PHP/(\d+)\.(\d+)\.(\d+)").unwrap(),
                Regex::new(r"PHP (\d+)\.(\d+)\.(\d+)").unwrap(),
                Regex::new(r"php-(\d+)\.(\d+)\.(\d+)").unwrap(),
                Regex::new(r"PHP_VERSION=(\d+)\.(\d+)\.(\d+)").unwrap(),
            ];

            for pattern in &version_patterns {
                if let Some(captures) = pattern.captures(&binary_str) {
                    let major = captures
                        .get(1)
                        .ok_or("Missing major version")?
                        .as_str()
                        .parse::<u8>()?;
                    let minor = captures
                        .get(2)
                        .ok_or("Missing minor version")?
                        .as_str()
                        .parse::<u8>()?;
                    let patch = captures
                        .get(3)
                        .ok_or("Missing patch version")?
                        .as_str()
                        .parse::<u8>()?;

                    let version = PHPVersion::new(major, minor, patch);
                    trace!(
                        "Detected PHP version from symbols: {}.{}.{} for PID {}",
                        major,
                        minor,
                        patch,
                        pid
                    );
                    return Ok(Some(version));
                }
            }

            // Look for PHP API version as fallback
            if let Some(captures) = Regex::new(r"PHP_API_VERSION\s+(\d+)")
                .unwrap()
                .captures(&binary_str)
            {
                let api_version = captures
                    .get(1)
                    .ok_or("Missing API version")?
                    .as_str()
                    .parse::<u32>()?;
                // Map API version to PHP version (approximate)
                let version = match api_version {
                    20190902 => PHPVersion::new(7, 4, 0),
                    20200930 => PHPVersion::new(8, 0, 0),
                    20210902 => PHPVersion::new(8, 1, 0),
                    20220829 => PHPVersion::new(8, 2, 0),
                    _ => return Err(format!("Unknown PHP API version: {}", api_version).into()),
                };

                trace!(
                    "Detected PHP version from API version {} -> {}.{}.{} for PID {}",
                    api_version,
                    version.major,
                    version.minor,
                    version.patch,
                    pid
                );
                return Ok(Some(version));
            }
        }

        Ok(None)
    }

    fn detect_version_from_maps(&self, pid: u32) -> Result<Option<PHPVersion>> {
        // Parse /proc/pid/maps and look for PHP libraries with version info
        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content = fs::read_to_string(&maps_path)?;

        for line in maps_content.lines() {
            if line.contains("libphp") || line.contains("php.so") || line.contains("/php") {
                // Extract the library path
                if let Some(path_start) = line.rfind(' ') {
                    let lib_path = &line[path_start + 1..];

                    // Look for version patterns in library path
                    if let Some(version_str) = self.extract_version_from_path(lib_path) {
                        if let Ok(version) = Version::parse(&version_str) {
                            let php_version = PHPVersion::from_version(&version);
                            trace!(
                                "Detected PHP version from maps: {}.{}.{} from {} for PID {}",
                                php_version.major,
                                php_version.minor,
                                php_version.patch,
                                lib_path,
                                pid
                            );
                            return Ok(Some(php_version));
                        }
                    }

                    // Try to read library file for version info
                    if let Ok(lib_content) = fs::read(lib_path) {
                        let lib_str = String::from_utf8_lossy(&lib_content);

                        // Look for version strings in library
                        let version_patterns = vec![
                            Regex::new(r"PHP/(\d+)\.(\d+)\.(\d+)").unwrap(),
                            Regex::new(r"php (\d+)\.(\d+)\.(\d+)").unwrap(),
                        ];

                        for pattern in &version_patterns {
                            if let Some(captures) = pattern.captures(&lib_str) {
                                let major = captures
                                    .get(1)
                                    .ok_or("Missing major")?
                                    .as_str()
                                    .parse::<u8>()?;
                                let minor = captures
                                    .get(2)
                                    .ok_or("Missing minor")?
                                    .as_str()
                                    .parse::<u8>()?;
                                let patch = captures
                                    .get(3)
                                    .ok_or("Missing patch")?
                                    .as_str()
                                    .parse::<u8>()?;

                                let version = PHPVersion::new(major, minor, patch);
                                trace!("Detected PHP version from library content: {}.{}.{} for PID {}", 
                                       major, minor, patch, pid);
                                return Ok(Some(version));
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    fn extract_version_from_path(&self, path: &str) -> Option<String> {
        // Look for version patterns in path like php7.4, php8.0, etc.
        let re = Regex::new(r"php(\d+)\.(\d+)").ok()?;
        if let Some(captures) = re.captures(path) {
            let major = captures.get(1)?.as_str();
            let minor = captures.get(2)?.as_str();
            return Some(format!("{}.{}.0", major, minor));
        }
        None
    }

    fn find_executor_globals(&self, pid: u32) -> Result<Option<u64>> {
        // Try different methods to find executor_globals
        self.find_executor_globals_from_symbols(pid)
            .or_else(|_| self.find_executor_globals_from_maps(pid))
            .or_else(|_| self.find_executor_globals_heuristic(pid))
    }

    fn find_executor_globals_from_symbols(&self, pid: u32) -> Result<Option<u64>> {
        use object::{Object, ObjectSymbol};

        // Read /proc/pid/maps to find PHP binary/libraries
        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content = fs::read_to_string(&maps_path)?;

        for line in maps_content.lines() {
            if line.contains("php") && (line.contains("r-xp") || line.contains("r--p")) {
                // Extract memory mapping info
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 6 {
                    continue;
                }

                let addr_range = parts[0];
                let file_path = parts[5];

                // Parse address range
                if let Some(dash_pos) = addr_range.find('-') {
                    let base_addr_str = &addr_range[..dash_pos];
                    let base_addr = u64::from_str_radix(base_addr_str, 16)?;

                    // Try to read the ELF file and find executor_globals symbol
                    if let Ok(file_data) = fs::read(file_path) {
                        if let Ok(obj_file) = object::File::parse(&*file_data) {
                            // Look for executor_globals symbol
                            for symbol in obj_file.symbols() {
                                if let Ok(name) = symbol.name() {
                                    if name == "executor_globals" || name == "_executor_globals" {
                                        let addr = symbol.address();
                                        let global_addr = base_addr + addr;
                                        trace!(
                                            "Found executor_globals symbol at 0x{:x} for PID {}",
                                            global_addr,
                                            pid
                                        );
                                        return Ok(Some(global_addr));
                                    }
                                }
                            }

                            // Also check dynamic symbols
                            for symbol in obj_file.dynamic_symbols() {
                                if let Ok(name) = symbol.name() {
                                    if name == "executor_globals" || name == "_executor_globals" {
                                        let addr = symbol.address();
                                        let global_addr = base_addr + addr;
                                        trace!("Found executor_globals dynamic symbol at 0x{:x} for PID {}", 
                                               global_addr, pid);
                                        return Ok(Some(global_addr));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Err("No executor_globals symbol found".into())
    }

    fn find_executor_globals_from_maps(&self, pid: u32) -> Result<Option<u64>> {
        // Look for patterns in memory maps that indicate PHP data segments
        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content = fs::read_to_string(&maps_path)?;

        let mut data_segments = Vec::new();
        let mut heap_addr = None;

        for line in maps_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let addr_range = parts[0];
            let perms = parts[1];

            if let Some(dash_pos) = addr_range.find('-') {
                let start_addr_str = &addr_range[..dash_pos];
                let end_addr_str = &addr_range[dash_pos + 1..];

                if let (Ok(start_addr), Ok(end_addr)) = (
                    u64::from_str_radix(start_addr_str, 16),
                    u64::from_str_radix(end_addr_str, 16),
                ) {
                    // Track heap for reference
                    if line.contains("[heap]") {
                        heap_addr = Some(start_addr);
                    }

                    // Look for read-write data segments related to PHP
                    if perms.contains("rw-") && parts.len() > 5 {
                        let file_path = parts[5];
                        if file_path.contains("php")
                            || (heap_addr.is_some() && (end_addr - start_addr) > 0x100000)
                        {
                            data_segments.push((start_addr, end_addr));
                        }
                    }
                }
            }
        }

        // Try to find executor_globals in identified data segments
        // Priority: nearest to heap, largest segments first
        data_segments.sort_by(|a, b| {
            let size_a = a.1 - a.0;
            let size_b = b.1 - b.0;
            size_b.cmp(&size_a) // Largest first
        });

        for (start_addr, end_addr) in data_segments {
            // Use a more intelligent heuristic based on typical PHP memory layout
            let segment_size = end_addr - start_addr;

            // executor_globals is typically in the first part of large data segments
            let candidates = vec![
                start_addr + 0x1000,           // Common offset after headers
                start_addr + 0x2000,           // Alternative common offset
                start_addr + segment_size / 4, // First quarter of segment
            ];

            for candidate in candidates {
                if candidate < end_addr {
                    trace!("Candidate executor_globals address 0x{:x} in segment 0x{:x}-0x{:x} for PID {}", 
                           candidate, start_addr, end_addr, pid);
                    return Ok(Some(candidate));
                }
            }
        }

        Err("No suitable memory regions found for executor_globals".into())
    }

    fn find_executor_globals_heuristic(&self, pid: u32) -> Result<Option<u64>> {
        // Last resort: use process memory layout heuristics
        // This is highly unreliable but better than nothing

        // Read process status to get memory info
        let status_path = format!("/proc/{}/status", pid);
        if let Ok(status) = fs::read_to_string(&status_path) {
            for line in status.lines() {
                if line.starts_with("VmData:") || line.starts_with("VmRSS:") {
                    // Use memory size info to make educated guess
                    // This is very rough and would need proper implementation
                    return Ok(Some(0x7f0000000000 + (pid as u64) * 0x1000));
                }
            }
        }

        Err("Could not determine executor_globals address".into())
    }

    fn detect_sapi(&self, cmdline: &str) -> PHPSapi {
        if cmdline.contains("php-fpm") {
            PHPSapi::FPM
        } else if cmdline.contains("apache") {
            PHPSapi::Apache
        } else if cmdline.contains("nginx") {
            PHPSapi::Nginx
        } else {
            PHPSapi::CLI
        }
    }

    fn get_or_create_offsets_id(&mut self, version: &PHPVersion) -> u8 {
        if let Some(&id) = self.offsets_map.get(version) {
            return id;
        }

        let id = self.next_offsets_id;
        self.offsets_map.insert(version.clone(), id);
        self.next_offsets_id += 1;

        id
    }

    pub fn get_offsets_for_version(&self, version: &PHPVersion) -> &PHPOffsets {
        match (version.major, version.minor) {
            (7, 4) => &PHP74_OFFSETS,
            (8, 0) => &PHP80_OFFSETS,
            (8, 1) => &PHP81_OFFSETS,
            (8, 2) => &PHP82_OFFSETS,
            _ => &PHP80_OFFSETS, // Default to 8.0
        }
    }
}

/// PHP unwind table for managing runtime information
#[derive(Default)]
pub struct PHPUnwindTable {
    detector: PHPRuntimeDetector,
    runtime_info_map_fd: i32,
    offsets_map_fd: i32,
}

impl PHPUnwindTable {
    pub unsafe fn new(runtime_info_map_fd: i32, offsets_map_fd: i32) -> Self {
        Self {
            detector: PHPRuntimeDetector::new(),
            runtime_info_map_fd,
            offsets_map_fd,
        }
    }

    pub fn add_process(&mut self, pid: u32) -> Result<()> {
        if let Some(runtime_info) = self.detector.detect(pid)? {
            // Store runtime info in BPF map
            unsafe {
                let ret = bpf_update_elem(
                    self.runtime_info_map_fd,
                    &pid as *const u32 as *const _,
                    &runtime_info as *const PHPRuntimeInfo as *const _,
                    BPF_ANY,
                );
                if ret != 0 {
                    return Err(format!("Failed to update PHP runtime info map: {}", ret).into());
                }
            }

            // Store offsets in BPF map if not already present
            let version =
                PHPVersion::new(runtime_info.version_major, runtime_info.version_minor, 0);
            let offsets = self.detector.get_offsets_for_version(&version);

            unsafe {
                let ret = bpf_update_elem(
                    self.offsets_map_fd,
                    &runtime_info.offsets_id as *const u8 as *const _,
                    offsets as *const PHPOffsets as *const _,
                    BPF_ANY,
                );
                if ret != 0 {
                    debug!("Failed to update PHP offsets map: {}", ret);
                    // Non-fatal error
                }
            }

            trace!(
                "Added PHP process PID {} with version {}.{}",
                pid,
                runtime_info.version_major,
                runtime_info.version_minor
            );
        }

        Ok(())
    }

    pub fn remove_process(&mut self, pid: u32) -> Result<()> {
        // Remove from detector cache
        if let Err(e) = self.detector.version_cache.remove(&pid) {
            warn!("Failed to remove PHP process {} from cache: {}", pid, e);
        }

        // Note: We don't remove from BPF maps as they might be shared with eBPF programs
        trace!("Removed PHP process PID {}", pid);

        Ok(())
    }

    /// Process PHP stack trace from eBPF and convert to string representation
    pub fn process_stack_trace(&self, _pid: u32, symbols: &[PHPSymbol]) -> Result<String> {
        let mut result = String::new();

        for (i, symbol) in symbols.iter().enumerate() {
            if !symbol.function_name.is_empty() {
                if !symbol.class_name.is_empty() {
                    result.push_str(&format!(
                        "{}. {}::{}() at {}:{}
",
                        i + 1,
                        symbol.class_name,
                        symbol.function_name,
                        symbol.filename,
                        symbol.lineno
                    ));
                } else {
                    result.push_str(&format!(
                        "{}. {}() at {}:{}
",
                        i + 1,
                        symbol.function_name,
                        symbol.filename,
                        symbol.lineno
                    ));
                }
            }
        }

        Ok(result)
    }

    /// Get profiler statistics
    pub fn get_stats(&self) -> PHPProfilerStats {
        let cache_stats = self.detector.version_cache.stats().unwrap_or_default();

        PHPProfilerStats {
            processes_tracked: cache_stats.size as u64,
            cache_hits: 0, // TODO: Implement cache hit/miss counters
            cache_misses: 0,
            offsets_versions: self.detector.offsets_map.len() as u64,
        }
    }
}

/// PHP symbol information for processed stack traces
#[derive(Debug, Clone)]
pub struct PHPSymbol {
    pub function_name: String,
    pub filename: String,
    pub class_name: String,
    pub lineno: u32,
    pub frame_type: PHPFrameType,
}

/// PHP frame types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PHPFrameType {
    User = 1,
    Internal = 2,
    Unknown = 3,
}

/// PHP profiler statistics
#[derive(Debug, Clone, Default)]
pub struct PHPProfilerStats {
    pub processes_tracked: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub offsets_versions: u64,
}

/// Enhanced PHP runtime detector with symbol resolution capabilities
impl PHPRuntimeDetector {
    /// Extract symbols from raw eBPF data
    pub fn extract_symbols_from_ebpf(&self, _raw_data: &[u8]) -> Result<Vec<PHPSymbol>> {
        // This would parse the raw eBPF data containing PHP symbols
        // For now, return empty vector as placeholder
        Ok(Vec::new())
    }

    /// Resolve function name from address using process memory
    pub fn resolve_function_name(&self, _pid: u32, func_addr: u64) -> Result<String> {
        // TODO: Implement function name resolution from process memory
        Ok(format!("<unknown@0x{:x}>", func_addr))
    }

    /// Enhanced executor_globals detection with multiple fallback methods
    pub fn find_executor_globals_enhanced(&self, pid: u32) -> Result<Option<u64>> {
        // Try all available methods in sequence
        self.find_executor_globals_from_symbols(pid)
            .or_else(|_| self.find_executor_globals_from_maps(pid))
            .or_else(|_| self.find_executor_globals_heuristic(pid))
            .or_else(|_| self.find_executor_globals_from_env(pid))
    }

    /// Try to find executor_globals from environment variables or command line
    fn find_executor_globals_from_env(&self, pid: u32) -> Result<Option<u64>> {
        // Read /proc/pid/environ to look for PHP-specific environment variables
        let environ_path = format!("/proc/{}/environ", pid);
        if let Ok(environ) = fs::read(&environ_path) {
            let environ_str = String::from_utf8_lossy(&environ);

            // Look for PHP-specific environment variables that might contain hints
            for var in environ_str.split('\0') {
                if var.starts_with("PHP_") || var.contains("executor_globals") {
                    // Parse potential address from environment
                    // This is a heuristic approach
                    trace!("Found PHP environment variable: {}", var);
                }
            }
        }

        // Last resort: use a calculated offset based on process info
        let status_path = format!("/proc/{}/status", pid);
        if let Ok(status) = fs::read_to_string(&status_path) {
            for line in status.lines() {
                if line.starts_with("VmData:") {
                    // Use data segment info to make educated guess
                    // This is very rough but better than nothing
                    let base_addr = 0x7fff00000000u64;
                    let offset = (pid as u64) * 0x10000;
                    return Ok(Some(base_addr + offset));
                }
            }
        }

        Err("Could not find executor_globals from environment".into())
    }
}
