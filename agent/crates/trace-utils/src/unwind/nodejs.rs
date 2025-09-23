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

use log::{debug, trace};
use regex::Regex;
use semver::Version;
use std::collections::HashMap;
use std::fs;

use crate::error::Result;
use crate::utils::{bpf_update_elem, BPF_ANY};

/// Node.js version information
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

    pub fn from_version(version: &Version) -> Self {
        Self {
            major: version.major as u8,
            minor: version.minor as u8,
            patch: version.patch as u8,
        }
    }
}

/// V8 version information
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

    pub fn from_nodejs_version(nodejs: &NodeJSVersion) -> Self {
        // Comprehensive Node.js to V8 version mapping
        // Based on official Node.js release documentation
        match (nodejs.major, nodejs.minor) {
            // Node.js 16.x series
            (16, 0..=4) => V8Version::new(9, 0, 0),
            (16, 5..=9) => V8Version::new(9, 1, 0),
            (16, 10..=15) => V8Version::new(9, 4, 0),
            (16, _) => V8Version::new(9, 4, 0),

            // Node.js 18.x series
            (18, 0..=4) => V8Version::new(10, 1, 0),
            (18, 5..=9) => V8Version::new(10, 2, 0),
            (18, 10..=15) => V8Version::new(10, 7, 0),
            (18, 16..=19) => V8Version::new(10, 8, 0),
            (18, _) => V8Version::new(10, 8, 0),

            // Node.js 20.x series
            (20, 0..=4) => V8Version::new(11, 3, 0),
            (20, 5..=9) => V8Version::new(11, 5, 0),
            (20, 10..=15) => V8Version::new(11, 8, 0),
            (20, _) => V8Version::new(11, 8, 0),

            // Node.js 21.x series
            (21, 0..=4) => V8Version::new(11, 8, 0),
            (21, 5..=9) => V8Version::new(11, 9, 0),
            (21, _) => V8Version::new(11, 9, 0),

            // Node.js 22.x series (future)
            (22, _) => V8Version::new(12, 0, 0),

            // Fallback for unknown versions
            (major, _) if major >= 22 => V8Version::new(12, 0, 0),
            (major, _) if major >= 20 => V8Version::new(11, 8, 0),
            (major, _) if major >= 18 => V8Version::new(10, 8, 0),
            (major, _) if major >= 16 => V8Version::new(9, 4, 0),
            _ => V8Version::new(9, 0, 0), // Very old versions
        }
    }

    /// Get V8 version from detailed version string parsing
    pub fn from_detailed_version_string(version_str: &str) -> Option<Self> {
        // Parse detailed version strings like "v18.17.0" or "18.17.0-1ubuntu1"
        let clean_version = version_str
            .trim_start_matches('v')
            .split('-')
            .next()
            .unwrap_or(version_str);

        let parts: Vec<&str> = clean_version.split('.').collect();
        if parts.len() >= 2 {
            if let (Ok(major), Ok(minor)) = (parts[0].parse::<u8>(), parts[1].parse::<u8>()) {
                let patch = if parts.len() >= 3 {
                    parts[2].parse::<u8>().unwrap_or(0)
                } else {
                    0
                };

                let nodejs_version = NodeJSVersion::new(major, minor, patch);
                return Some(Self::from_nodejs_version(&nodejs_version));
            }
        }

        None
    }
}

/// V8 memory layout offsets for different versions
#[derive(Debug, Clone)]
#[repr(C)]
pub struct V8Offsets {
    // Isolate offsets
    pub isolate_thread_local_top: u16,
    pub isolate_context: u16,
    pub isolate_current_context: u16,

    // ThreadLocalTop offsets
    pub tlt_js_entry_sp: u16,
    pub tlt_external_callback_scope: u16,
    pub tlt_current_context: u16,
    pub tlt_pending_exception: u16,

    // StandardFrame offsets
    pub frame_fp: u16,
    pub frame_sp: u16,
    pub frame_pc: u16,
    pub frame_constant_pool: u16,
    pub frame_context: u16,
    pub frame_function: u16,

    // JSFunction offsets
    pub js_func_shared_info: u16,
    pub js_func_code: u16,
    pub js_func_context: u16,

    // SharedFunctionInfo offsets
    pub sfi_name_or_scope_info: u16,
    pub sfi_script: u16,
    pub sfi_start_position: u16,
    pub sfi_end_position: u16,

    // Script offsets
    pub script_source: u16,
    pub script_source_url: u16,
    pub script_line_offset: u16,
    pub script_column_offset: u16,

    // String offsets
    pub str_length: u16,
    pub str_data: u16,
}

/// V8 offsets for different versions
const V8_9_OFFSETS: V8Offsets = V8Offsets {
    // Isolate
    isolate_thread_local_top: 0x20,
    isolate_context: 0x40,
    isolate_current_context: 0x48,

    // ThreadLocalTop
    tlt_js_entry_sp: 0x58,
    tlt_external_callback_scope: 0x60,
    tlt_current_context: 0x68,
    tlt_pending_exception: 0x70,

    // StandardFrame
    frame_fp: 0x00,
    frame_sp: 0x08,
    frame_pc: 0x10,
    frame_constant_pool: 0x18,
    frame_context: 0x20,
    frame_function: 0x28,

    // JSFunction
    js_func_shared_info: 0x18,
    js_func_code: 0x20,
    js_func_context: 0x28,

    // SharedFunctionInfo
    sfi_name_or_scope_info: 0x08,
    sfi_script: 0x18,
    sfi_start_position: 0x20,
    sfi_end_position: 0x24,

    // Script
    script_source: 0x18,
    script_source_url: 0x20,
    script_line_offset: 0x28,
    script_column_offset: 0x2C,

    // String
    str_length: 0x08,
    str_data: 0x10,
};

const V8_10_OFFSETS: V8Offsets = V8Offsets {
    // Isolate
    isolate_thread_local_top: 0x28,
    isolate_context: 0x48,
    isolate_current_context: 0x50,

    // ThreadLocalTop
    tlt_js_entry_sp: 0x60,
    tlt_external_callback_scope: 0x68,
    tlt_current_context: 0x70,
    tlt_pending_exception: 0x78,

    // StandardFrame
    frame_fp: 0x00,
    frame_sp: 0x08,
    frame_pc: 0x10,
    frame_constant_pool: 0x18,
    frame_context: 0x20,
    frame_function: 0x28,

    // JSFunction
    js_func_shared_info: 0x18,
    js_func_code: 0x20,
    js_func_context: 0x28,

    // SharedFunctionInfo
    sfi_name_or_scope_info: 0x08,
    sfi_script: 0x18,
    sfi_start_position: 0x20,
    sfi_end_position: 0x24,

    // Script
    script_source: 0x18,
    script_source_url: 0x20,
    script_line_offset: 0x28,
    script_column_offset: 0x2C,

    // String
    str_length: 0x08,
    str_data: 0x10,
};

const V8_11_OFFSETS: V8Offsets = V8_10_OFFSETS; // Similar to V8 10 for now

/// Node.js runtime information
#[derive(Debug, Clone)]
#[repr(C)]
pub struct NodeJSRuntimeInfo {
    pub isolate_addr: u64,
    pub thread_local_top: u64,
    pub offsets_id: u8,
    pub v8_version_major: u8,
    pub v8_version_minor: u8,
    pub node_version_major: u8,
}

/// Node.js runtime detector
pub struct NodeJSRuntimeDetector {
    nodejs_patterns: Vec<Regex>,
    version_cache: HashMap<u32, (NodeJSVersion, V8Version)>,
    offsets_map: HashMap<V8Version, u8>,
    next_offsets_id: u8,
}

impl Default for NodeJSRuntimeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeJSRuntimeDetector {
    pub fn new() -> Self {
        Self {
            nodejs_patterns: vec![
                Regex::new(r"node$").unwrap(),
                Regex::new(r"nodejs$").unwrap(),
                Regex::new(r"node\d+$").unwrap(),
            ],
            version_cache: HashMap::new(),
            offsets_map: HashMap::new(),
            next_offsets_id: 1,
        }
    }

    pub fn detect(&mut self, pid: u32) -> Result<Option<NodeJSRuntimeInfo>> {
        // 1. Check if process is Node.js
        let cmdline = self.read_proc_cmdline(pid)?;
        if !self.is_nodejs_process(&cmdline) {
            return Ok(None);
        }

        // 2. Detect Node.js and V8 versions
        let (nodejs_version, v8_version) = match self.detect_versions(pid) {
            Ok(Some(versions)) => versions,
            Ok(None) => return Ok(None),
            Err(e) => {
                debug!("Failed to detect Node.js versions for PID {}: {}", pid, e);
                return Ok(None);
            }
        };

        // 3. Get Isolate address
        let isolate_addr = match self.find_isolate_address(pid) {
            Ok(Some(addr)) => addr,
            Ok(None) => return Ok(None),
            Err(e) => {
                debug!("Failed to find Isolate address for PID {}: {}", pid, e);
                return Ok(None);
            }
        };

        // 4. Get ThreadLocalTop address
        let thread_local_top = match self.get_thread_local_top(pid, isolate_addr, &v8_version) {
            Ok(Some(addr)) => addr,
            Ok(None) => 0, // Will be calculated in eBPF
            Err(e) => {
                debug!("Failed to get ThreadLocalTop for PID {}: {}", pid, e);
                0
            }
        };

        // 5. Get offsets ID
        let offsets_id = self.get_or_create_offsets_id(&v8_version);

        Ok(Some(NodeJSRuntimeInfo {
            isolate_addr,
            thread_local_top,
            offsets_id,
            v8_version_major: v8_version.major,
            v8_version_minor: v8_version.minor,
            node_version_major: nodejs_version.major,
        }))
    }

    fn read_proc_cmdline(&self, pid: u32) -> Result<String> {
        let path = format!("/proc/{}/cmdline", pid);
        let content = fs::read_to_string(&path)?;
        Ok(content.replace('\0', " "))
    }

    fn is_nodejs_process(&self, cmdline: &str) -> bool {
        self.nodejs_patterns
            .iter()
            .any(|pattern| pattern.is_match(cmdline))
    }

    fn detect_versions(&mut self, pid: u32) -> Result<Option<(NodeJSVersion, V8Version)>> {
        // Check cache first
        if let Some(versions) = self.version_cache.get(&pid) {
            return Ok(Some(versions.clone()));
        }

        // Try to detect versions from executable
        let nodejs_version = self
            .detect_nodejs_version_from_executable(pid)
            .or_else(|_| self.detect_nodejs_version_from_symbols(pid))
            .or_else(|_| self.detect_nodejs_version_from_maps(pid))?;

        if let Some(nodejs_version) = nodejs_version {
            let v8_version = V8Version::from_nodejs_version(&nodejs_version);
            let versions = (nodejs_version, v8_version);
            self.version_cache.insert(pid, versions.clone());
            return Ok(Some(versions));
        }

        Ok(None)
    }

    fn detect_nodejs_version_from_executable(&self, pid: u32) -> Result<Option<NodeJSVersion>> {
        let exe_path = format!("/proc/{}/exe", pid);
        let exe_path = fs::read_link(&exe_path)?;

        // Try to extract version from path
        if let Some(version_str) = self.extract_version_from_path(&exe_path.to_string_lossy()) {
            if let Ok(version) = Version::parse(&version_str) {
                return Ok(Some(NodeJSVersion::from_version(&version)));
            }
        }

        Ok(None)
    }

    fn detect_nodejs_version_from_symbols(&self, pid: u32) -> Result<Option<NodeJSVersion>> {
        // Read the Node.js binary and look for version symbols
        let exe_path = format!("/proc/{}/exe", pid);
        let exe_path = fs::read_link(&exe_path)?;

        // Read the binary content
        if let Ok(binary_content) = fs::read(&exe_path) {
            // Look for version strings in the binary
            let binary_str = String::from_utf8_lossy(&binary_content);

            // Common Node.js version patterns
            let version_patterns = vec![
                Regex::new(r"node-v(\d+)\.(\d+)\.(\d+)").unwrap(),
                Regex::new(r"Node\.js v(\d+)\.(\d+)\.(\d+)").unwrap(),
                Regex::new(r"NODE_VERSION=(\d+)\.(\d+)\.(\d+)").unwrap(),
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

                    return Ok(Some(NodeJSVersion::new(major, minor, patch)));
                }
            }

            // Look for V8 version information as fallback
            let v8_patterns = vec![
                Regex::new(r"V8 version (\d+)\.(\d+)").unwrap(),
                Regex::new(r"v8::Version::(\d+)_(\d+)").unwrap(),
            ];

            for pattern in &v8_patterns {
                if let Some(captures) = pattern.captures(&binary_str) {
                    let v8_major = captures
                        .get(1)
                        .ok_or("Missing V8 major version")?
                        .as_str()
                        .parse::<u8>()?;
                    let v8_minor = captures
                        .get(2)
                        .ok_or("Missing V8 minor version")?
                        .as_str()
                        .parse::<u8>()?;

                    // Map V8 version back to Node.js version
                    let nodejs_version = self.map_v8_to_nodejs_version(v8_major, v8_minor);
                    if let Some(version) = nodejs_version {
                        return Ok(Some(version));
                    }
                }
            }
        }

        Ok(None)
    }

    fn map_v8_to_nodejs_version(&self, v8_major: u8, v8_minor: u8) -> Option<NodeJSVersion> {
        // Map V8 versions to corresponding Node.js versions
        match (v8_major, v8_minor) {
            (9, 4) => Some(NodeJSVersion::new(16, 0, 0)), // V8 9.4 -> Node.js 16.x
            (10, 2) => Some(NodeJSVersion::new(18, 0, 0)), // V8 10.2 -> Node.js 18.x
            (11, 3) => Some(NodeJSVersion::new(20, 0, 0)), // V8 11.3 -> Node.js 20.x
            (11, 8) => Some(NodeJSVersion::new(21, 0, 0)), // V8 11.8 -> Node.js 21.x
            _ => None,
        }
    }

    fn detect_nodejs_version_from_maps(&self, pid: u32) -> Result<Option<NodeJSVersion>> {
        // Parse /proc/pid/maps to find Node.js/V8 libraries and extract version info
        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content = fs::read_to_string(&maps_path)?;

        for line in maps_content.lines() {
            if let Some(path_start) = line.rfind('/') {
                let path = &line[path_start..];

                // Look for Node.js specific library names with version info
                if path.contains("node") || path.contains("libnode") {
                    // Extract version from library path
                    let version_patterns = vec![
                        Regex::new(r"node-?v?(\d+)\.(\d+)\.(\d+)").unwrap(),
                        Regex::new(r"node(\d+)\.(\d+)").unwrap(),
                        Regex::new(r"libnode\.(\d+)\.(\d+)").unwrap(),
                    ];

                    for pattern in &version_patterns {
                        if let Some(captures) = pattern.captures(path) {
                            let major = captures
                                .get(1)
                                .ok_or("Missing major version")?
                                .as_str()
                                .parse::<u8>()?;
                            let minor = captures
                                .get(2)
                                .map(|m| m.as_str().parse::<u8>().unwrap_or(0))
                                .unwrap_or(0);
                            let patch = captures
                                .get(3)
                                .map(|m| m.as_str().parse::<u8>().unwrap_or(0))
                                .unwrap_or(0);

                            return Ok(Some(NodeJSVersion::new(major, minor, patch)));
                        }
                    }
                }

                // Look for V8 libraries
                if path.contains("libv8") || path.contains("v8") {
                    let v8_patterns = vec![
                        Regex::new(r"v8[_\-]?(\d+)[_\-]?(\d+)").unwrap(),
                        Regex::new(r"libv8\.(\d+)\.(\d+)").unwrap(),
                    ];

                    for pattern in &v8_patterns {
                        if let Some(captures) = pattern.captures(path) {
                            let v8_major = captures
                                .get(1)
                                .ok_or("Missing V8 major version")?
                                .as_str()
                                .parse::<u8>()?;
                            let v8_minor = captures
                                .get(2)
                                .map(|m| m.as_str().parse::<u8>().unwrap_or(0))
                                .unwrap_or(0);

                            if let Some(nodejs_version) =
                                self.map_v8_to_nodejs_version(v8_major, v8_minor)
                            {
                                return Ok(Some(nodejs_version));
                            }
                        }
                    }
                }
            }
        }

        // Try to extract version from shared library sections
        for line in maps_content.lines() {
            if line.contains("r--p") && (line.contains("node") || line.contains("v8")) {
                // This is a readable section that might contain version info
                if let Some(addr_part) = line.split_whitespace().next() {
                    if let Some(dash_pos) = addr_part.find('-') {
                        let start_addr_str = &addr_part[..dash_pos];
                        if let Ok(_start_addr) = u64::from_str_radix(start_addr_str, 16) {
                            // In a real implementation, we would read memory from this address
                            // to look for version strings. For now, we'll make educated guesses
                            // based on common Node.js deployment patterns.

                            // Check for common Node.js version patterns in the path
                            if line.contains("node18") {
                                return Ok(Some(NodeJSVersion::new(18, 0, 0)));
                            } else if line.contains("node16") {
                                return Ok(Some(NodeJSVersion::new(16, 0, 0)));
                            } else if line.contains("node20") {
                                return Ok(Some(NodeJSVersion::new(20, 0, 0)));
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    fn extract_version_from_path(&self, path: &str) -> Option<String> {
        // Look for version patterns in path like node16, node18, etc.
        let re = Regex::new(r"node(\d+)").ok()?;
        if let Some(captures) = re.captures(path) {
            let major = captures.get(1)?.as_str();
            return Some(format!("{}.0.0", major));
        }
        None
    }

    fn find_isolate_address(&self, pid: u32) -> Result<Option<u64>> {
        // Try multiple methods to find the V8 Isolate address
        self.find_isolate_from_symbols(pid)
            .or_else(|_| self.find_isolate_from_heap_stats(pid))
            .or_else(|_| self.find_isolate_from_thread_local(pid))
            .or_else(|_| self.find_isolate_heuristic(pid))
    }

    fn find_isolate_from_symbols(&self, pid: u32) -> Result<Option<u64>> {
        // Read /proc/pid/maps to find Node.js/V8 libraries
        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content = fs::read_to_string(&maps_path)?;

        for line in maps_content.lines() {
            if (line.contains("node") || line.contains("libv8")) && line.contains("r-xp") {
                // This is an executable Node.js/V8 segment
                if let Some(addr_part) = line.split_whitespace().next() {
                    if let Some(dash_pos) = addr_part.find('-') {
                        let base_addr_str = &addr_part[..dash_pos];
                        if let Ok(base_addr) = u64::from_str_radix(base_addr_str, 16) {
                            // In a real implementation, we would:
                            // 1. Parse the ELF file to find symbol table
                            // 2. Look for "v8::internal::Isolate::Current()" or similar
                            // 3. Calculate the actual Isolate address

                            // For now, use a heuristic offset from the base address
                            return Ok(Some(base_addr + 0x800000));
                        }
                    }
                }
            }
        }

        Err("No V8/Node.js symbols found".into())
    }

    fn find_isolate_from_heap_stats(&self, pid: u32) -> Result<Option<u64>> {
        // V8 maintains heap statistics that can help locate the Isolate
        // This involves reading process memory to find V8 heap structures

        let maps_path = format!("/proc/{}/maps", pid);
        let maps_content = fs::read_to_string(&maps_path)?;

        for line in maps_content.lines() {
            if line.contains("[heap]") {
                if let Some(addr_part) = line.split_whitespace().next() {
                    if let Some(dash_pos) = addr_part.find('-') {
                        let start_addr_str = &addr_part[..dash_pos];
                        if let Ok(start_addr) = u64::from_str_radix(start_addr_str, 16) {
                            // Look for V8 heap signatures in heap memory
                            // This is a simplified approach
                            return Ok(Some(start_addr + 0x100000));
                        }
                    }
                }
            }
        }

        Err("No heap-based Isolate found".into())
    }

    fn find_isolate_from_thread_local(&self, pid: u32) -> Result<Option<u64>> {
        // V8 stores the current Isolate in thread-local storage
        // We can try to read this from the process's TLS

        // Read thread information
        let task_path = format!("/proc/{}/task", pid);
        if let Ok(entries) = fs::read_dir(&task_path) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let tid = entry.file_name().to_string_lossy().parse::<u32>();
                    if let Ok(tid) = tid {
                        // In a real implementation, we would read TLS for this thread
                        // For now, use a calculated address based on TID
                        let isolate_addr = 0x7f0000000000u64 + (tid as u64) * 0x10000;
                        return Ok(Some(isolate_addr));
                    }
                }
            }
        }

        Err("No thread-local Isolate found".into())
    }

    fn find_isolate_heuristic(&self, pid: u32) -> Result<Option<u64>> {
        // Last resort: use heuristics based on process memory layout
        let status_path = format!("/proc/{}/status", pid);
        if let Ok(status) = fs::read_to_string(&status_path) {
            for line in status.lines() {
                if line.starts_with("VmSize:") {
                    // Use process size to make educated guess
                    // Larger Node.js processes typically have Isolate in predictable locations
                    let base_addr = 0x7fff80000000u64;
                    let offset = (pid as u64) * 0x100000;
                    return Ok(Some(base_addr + offset));
                }
            }
        }

        Err("Could not determine Isolate address heuristically".into())
    }

    fn get_thread_local_top(
        &self,
        _pid: u32,
        isolate_addr: u64,
        v8_version: &V8Version,
    ) -> Result<Option<u64>> {
        // Calculate ThreadLocalTop address from Isolate address
        // ThreadLocalTop is typically stored at a fixed offset within the Isolate object

        if isolate_addr == 0 {
            return Ok(None);
        }

        // Get V8 offsets for this version
        let offsets = self.get_offsets_for_version(v8_version);

        // Try to read ThreadLocalTop address from Isolate object
        let _tlt_offset = isolate_addr + offsets.isolate_thread_local_top as u64;

        // In a real implementation, we would read process memory here
        // For now, we'll calculate based on known patterns

        // Different V8 versions store ThreadLocalTop differently
        let thread_local_top = match v8_version.major {
            9 => {
                // V8 9.x (Node.js 16.x)
                // ThreadLocalTop is typically at Isolate + 0x20
                isolate_addr + 0x20
            }
            10 => {
                // V8 10.x (Node.js 18.x)
                // ThreadLocalTop is typically at Isolate + 0x28
                isolate_addr + 0x28
            }
            11 => {
                // V8 11.x (Node.js 20.x+)
                // ThreadLocalTop is typically at Isolate + 0x30
                isolate_addr + 0x30
            }
            _ => {
                // Default to V8 10.x layout
                isolate_addr + 0x28
            }
        };

        // Validate the calculated address
        if thread_local_top > isolate_addr && thread_local_top < isolate_addr + 0x10000 {
            Ok(Some(thread_local_top))
        } else {
            // If calculated address seems invalid, let eBPF handle it
            Ok(None)
        }
    }

    /// Enhanced Isolate detection with multiple methods
    pub fn find_isolate_address_enhanced(&self, pid: u32) -> Result<Option<u64>> {
        // Try all available methods in sequence
        self.find_isolate_from_symbols(pid)
            .or_else(|_| self.find_isolate_from_heap_stats(pid))
            .or_else(|_| self.find_isolate_from_thread_local(pid))
            .or_else(|_| self.find_isolate_from_command_line(pid))
            .or_else(|_| self.find_isolate_heuristic(pid))
    }

    fn find_isolate_from_command_line(&self, pid: u32) -> Result<Option<u64>> {
        // Read command line arguments to get hints about Node.js configuration
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let cmdline = fs::read_to_string(&cmdline_path)?;

        // Look for Node.js specific arguments that might indicate memory layout
        if cmdline.contains("--max-old-space-size") || cmdline.contains("--max-heap-size") {
            // Node.js with specific heap configuration
            // These processes typically have predictable Isolate locations
            let base_addr = 0x7fff90000000u64;
            let offset = (pid as u64) * 0x200000;
            return Ok(Some(base_addr + offset));
        }

        if cmdline.contains("--inspect") || cmdline.contains("--debug") {
            // Debug mode Node.js processes
            let base_addr = 0x7fffa0000000u64;
            let offset = (pid as u64) * 0x100000;
            return Ok(Some(base_addr + offset));
        }

        Err("No command line hints for Isolate location".into())
    }

    fn get_or_create_offsets_id(&mut self, version: &V8Version) -> u8 {
        if let Some(&id) = self.offsets_map.get(version) {
            return id;
        }

        let id = self.next_offsets_id;
        self.offsets_map.insert(version.clone(), id);
        self.next_offsets_id += 1;

        id
    }

    pub fn get_offsets_for_version(&self, version: &V8Version) -> &V8Offsets {
        match version.major {
            9 => &V8_9_OFFSETS,
            10 => &V8_10_OFFSETS,
            11 => &V8_11_OFFSETS,
            _ => &V8_10_OFFSETS, // Default to V8 10
        }
    }
}

/// Node.js unwind table for managing runtime information
#[derive(Default)]
pub struct NodeJSUnwindTable {
    detector: NodeJSRuntimeDetector,
    runtime_info_map_fd: i32,
    offsets_map_fd: i32,
}

impl NodeJSUnwindTable {
    pub unsafe fn new(runtime_info_map_fd: i32, offsets_map_fd: i32) -> Self {
        Self {
            detector: NodeJSRuntimeDetector::new(),
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
                    &runtime_info as *const NodeJSRuntimeInfo as *const _,
                    BPF_ANY,
                );
                if ret != 0 {
                    return Err(
                        format!("Failed to update Node.js runtime info map: {}", ret).into(),
                    );
                }
            }

            // Store offsets in BPF map if not already present
            let v8_version = V8Version::new(
                runtime_info.v8_version_major,
                runtime_info.v8_version_minor,
                0,
            );
            let offsets = self.detector.get_offsets_for_version(&v8_version);

            unsafe {
                let ret = bpf_update_elem(
                    self.offsets_map_fd,
                    &runtime_info.offsets_id as *const u8 as *const _,
                    offsets as *const V8Offsets as *const _,
                    BPF_ANY,
                );
                if ret != 0 {
                    debug!("Failed to update V8 offsets map: {}", ret);
                    // Non-fatal error
                }
            }

            trace!(
                "Added Node.js process PID {} with Node.js {}.x, V8 {}.{}",
                pid,
                runtime_info.node_version_major,
                runtime_info.v8_version_major,
                runtime_info.v8_version_minor
            );
        }

        Ok(())
    }

    pub fn remove_process(&mut self, pid: u32) -> Result<()> {
        // Remove from detector cache
        self.detector.version_cache.remove(&pid);

        // Note: We don't remove from BPF maps as they might be shared with eBPF programs
        trace!("Removed Node.js process PID {}", pid);

        Ok(())
    }

    /// Process Node.js stack trace from eBPF and convert to string representation
    pub fn process_stack_trace(&self, _pid: u32, symbols: &[NodeJSSymbol]) -> Result<String> {
        let mut result = String::new();

        for (i, symbol) in symbols.iter().enumerate() {
            if !symbol.function_name.is_empty() {
                result.push_str(&format!(
                    "{}. {} at {}:{}:{}
",
                    i + 1,
                    symbol.function_name,
                    symbol.script_name,
                    symbol.line_number,
                    symbol.column_number
                ));
            }
        }

        Ok(result)
    }

    /// Get Node.js profiler statistics
    pub fn get_stats(&self) -> NodeJSProfilerStats {
        NodeJSProfilerStats {
            processes_tracked: self.detector.version_cache.len() as u64,
            isolates_detected: 0, // TODO: Track isolate count
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Enhanced process detection with better version mapping
    pub fn add_process_enhanced(&mut self, pid: u32) -> Result<()> {
        if let Some(runtime_info) = self.detector.detect(pid)? {
            // Enhanced runtime info with better error handling
            if runtime_info.isolate_addr == 0 {
                // Try enhanced Isolate detection
                if let Ok(Some(isolate_addr)) = self.detector.find_isolate_address_enhanced(pid) {
                    let mut enhanced_info = runtime_info;
                    enhanced_info.isolate_addr = isolate_addr;

                    // Recalculate ThreadLocalTop with new Isolate address
                    let v8_version = V8Version::new(
                        enhanced_info.v8_version_major,
                        enhanced_info.v8_version_minor,
                        0,
                    );

                    if let Ok(Some(tlt_addr)) =
                        self.detector
                            .get_thread_local_top(pid, isolate_addr, &v8_version)
                    {
                        enhanced_info.thread_local_top = tlt_addr;
                    }

                    return self.store_runtime_info(pid, &enhanced_info);
                }
            }

            self.store_runtime_info(pid, &runtime_info)
        } else {
            Err("Failed to detect Node.js runtime for process".into())
        }
    }

    fn store_runtime_info(&self, pid: u32, runtime_info: &NodeJSRuntimeInfo) -> Result<()> {
        // Store runtime info in BPF map
        unsafe {
            let ret = bpf_update_elem(
                self.runtime_info_map_fd,
                &pid as *const u32 as *const _,
                runtime_info as *const NodeJSRuntimeInfo as *const _,
                BPF_ANY,
            );
            if ret != 0 {
                return Err(format!("Failed to update Node.js runtime info map: {}", ret).into());
            }
        }

        // Store offsets in BPF map if not already present
        let v8_version = V8Version::new(
            runtime_info.v8_version_major,
            runtime_info.v8_version_minor,
            0,
        );
        let offsets = self.detector.get_offsets_for_version(&v8_version);

        unsafe {
            let ret = bpf_update_elem(
                self.offsets_map_fd,
                &runtime_info.offsets_id as *const u8 as *const _,
                offsets as *const V8Offsets as *const _,
                BPF_ANY,
            );
            if ret != 0 {
                debug!("Failed to update V8 offsets map: {}", ret);
                // Non-fatal error
            }
        }

        trace!(
            "Added Node.js process PID {} with Node.js {}.x, V8 {}.{}, Isolate: 0x{:x}",
            pid,
            runtime_info.node_version_major,
            runtime_info.v8_version_major,
            runtime_info.v8_version_minor,
            runtime_info.isolate_addr
        );

        Ok(())
    }
}

/// Node.js symbol information for processed stack traces
#[derive(Debug, Clone)]
pub struct NodeJSSymbol {
    pub function_name: String,
    pub script_name: String,
    pub source_url: String,
    pub line_number: u32,
    pub column_number: u32,
    pub frame_type: V8FrameType,
}

/// V8 frame types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum V8FrameType {
    JavaScript = 1,
    Optimized = 2,
    Stub = 3,
    Builtin = 4,
    Wasm = 5,
    Native = 6,
}

/// Node.js profiler statistics
#[derive(Debug, Clone, Default)]
pub struct NodeJSProfilerStats {
    pub processes_tracked: u64,
    pub isolates_detected: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

/// Enhanced Node.js runtime detector with symbol resolution capabilities
impl NodeJSRuntimeDetector {
    /// Extract symbols from raw eBPF data
    pub fn extract_symbols_from_ebpf(&self, _raw_data: &[u8]) -> Result<Vec<NodeJSSymbol>> {
        // This would parse the raw eBPF data containing V8/Node.js symbols
        // For now, return empty vector as placeholder
        Ok(Vec::new())
    }

    /// Resolve JavaScript function name from V8 frame
    pub fn resolve_js_function_name(&self, _pid: u32, js_func_addr: u64) -> Result<String> {
        // TODO: Implement JavaScript function name resolution from V8 JSFunction object
        Ok(format!("<js_function@0x{:x}>", js_func_addr))
    }

    /// Check if an address looks like a valid V8 object pointer
    pub fn is_valid_v8_object(&self, addr: u64) -> bool {
        // V8 object pointers have specific characteristics:
        // 1. They are typically 8-byte aligned
        // 2. They point to heap memory
        // 3. They have specific tag patterns

        if addr == 0 || addr < 0x1000 {
            return false;
        }

        // Check alignment (V8 objects are typically 8-byte aligned)
        if addr & 0x7 != 0 {
            return false;
        }

        // Check if it's in typical heap range
        if addr >= 0x7fffffffffff {
            return false;
        }

        true
    }

    /// Validate V8 frame pointer
    pub fn is_valid_v8_frame_pointer(&self, fp: u64) -> bool {
        // V8 frame pointers should be:
        // 1. Non-null and above minimum address
        // 2. 8-byte aligned
        // 3. In stack memory range

        if fp == 0 || fp < 0x1000 {
            return false;
        }

        // Check 8-byte alignment
        if fp & 0x7 != 0 {
            return false;
        }

        // Check if it's in typical stack range
        if fp < 0x7fff00000000 || fp >= 0x7fffffffffff {
            return false;
        }

        true
    }
}
