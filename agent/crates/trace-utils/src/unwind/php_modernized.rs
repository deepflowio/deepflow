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

//! Modernized PHP stack unwinding with unified version-specific offsets
//!
//! This module replaces the hardcoded offset approach with the new
//! VersionSpecificOffsetManager system for better maintainability and accuracy.

use crate::unwind::version_manager::VersionSpecificOffsetManager;
use crate::unwind::version_specific_offsets::*;
use log::{debug, trace, warn};
use std::sync::Arc;

use crate::error::Result;
use crate::utils::{bpf_update_elem, BPF_ANY};

/// Modernized PHP SAPI (Server API) types
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

/// PHP runtime information for BPF maps
#[derive(Debug, Clone)]
#[repr(C)]
pub struct PHPRuntimeInfo {
    pub version: u32,
    pub sapi: PHPSapi,
    pub executor_globals_addr: u64,
    pub offsets: PHPOffsets,
}

/// Modernized PHP stack unwinding table
/// Uses the new unified version-specific offset system
pub struct ModernizedPHPUnwindTable {
    /// Unified version-specific offset manager
    offset_manager: Arc<VersionSpecificOffsetManager>,

    /// BPF map file descriptors
    runtime_info_map_fd: i32,
    offsets_map_fd: i32,

    /// Performance statistics
    detection_count: std::sync::atomic::AtomicU64,
    success_count: std::sync::atomic::AtomicU64,
    error_count: std::sync::atomic::AtomicU64,
}

impl ModernizedPHPUnwindTable {
    /// Create a new modernized PHP unwind table
    pub unsafe fn new(runtime_info_map_fd: i32, offsets_map_fd: i32) -> Self {
        Self {
            offset_manager: Arc::new(VersionSpecificOffsetManager::new()),
            runtime_info_map_fd,
            offsets_map_fd,
            detection_count: std::sync::atomic::AtomicU64::new(0),
            success_count: std::sync::atomic::AtomicU64::new(0),
            error_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Add a PHP process to the unwind table
    /// Uses the new version-specific offset detection system
    pub fn add_process(&mut self, pid: u32) -> Result<()> {
        self.detection_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        trace!("Adding PHP process {} to unwind table", pid);

        // Use the new offset manager to detect PHP runtime
        match self.offset_manager.detect_php_runtime(pid) {
            Ok(runtime_info) => {
                debug!(
                    "Detected PHP {} for process {} with executor_globals at 0x{:x}",
                    runtime_info.version, pid, runtime_info.executor_globals_address
                );

                // Convert to BPF-compatible format
                let bpf_runtime_info = PHPRuntimeInfo {
                    version: runtime_info.version.to_u32(),
                    sapi: self.detect_sapi(pid),
                    executor_globals_addr: runtime_info.executor_globals_address,
                    offsets: *runtime_info.offsets,
                };

                // Store in BPF maps
                self.store_runtime_info(pid, &bpf_runtime_info)?;

                self.success_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to detect PHP runtime for process {}: {}", pid, e);
                self.error_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(format!("{}", e).into())
            }
        }
    }

    /// Remove a PHP process from the unwind table
    pub fn remove_process(&mut self, pid: u32) {
        trace!("Removing PHP process {} from unwind table", pid);

        // Clear from offset manager cache
        self.offset_manager.clear_process_cache(pid);

        // Remove from BPF maps
        unsafe {
            let ret = libc::syscall(
                libc::SYS_bpf,
                2, // BPF_MAP_DELETE_ELEM
                &pid as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>(),
            );

            if ret != 0 {
                debug!("Failed to remove process {} from BPF map: {}", pid, ret);
            }
        }
    }

    /// Get performance statistics
    pub fn get_stats(&self) -> PHPUnwindStats {
        PHPUnwindStats {
            detection_count: self
                .detection_count
                .load(std::sync::atomic::Ordering::Relaxed),
            success_count: self
                .success_count
                .load(std::sync::atomic::Ordering::Relaxed),
            error_count: self.error_count.load(std::sync::atomic::Ordering::Relaxed),
            manager_stats: self.offset_manager.get_stats(),
        }
    }

    /// Detect PHP SAPI type from process information
    fn detect_sapi(&self, pid: u32) -> PHPSapi {
        // Try to read the executable name
        if let Ok(exe_path) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
            if let Some(exe_name) = exe_path.file_name().and_then(|n| n.to_str()) {
                return PHPSapi::from(exe_name);
            }
        }

        // Try to read command line
        if let Ok(cmdline) = std::fs::read_to_string(format!("/proc/{}/cmdline", pid)) {
            if cmdline.contains("php-fpm") {
                return PHPSapi::FPM;
            }
            if cmdline.contains("apache") {
                return PHPSapi::Apache;
            }
            if cmdline.contains("nginx") {
                return PHPSapi::Nginx;
            }
        }

        PHPSapi::Unknown
    }

    /// Store runtime information in BPF maps
    fn store_runtime_info(&self, pid: u32, runtime_info: &PHPRuntimeInfo) -> Result<()> {
        unsafe {
            // Store runtime info
            let ret = bpf_update_elem(
                self.runtime_info_map_fd,
                &pid as *const u32 as *const libc::c_void,
                runtime_info as *const PHPRuntimeInfo as *const libc::c_void,
                BPF_ANY,
            );

            if ret != 0 {
                return Err(format!(
                    "Failed to store PHP runtime info for process {}: {}",
                    pid, ret
                )
                .into());
            }

            // Store offsets separately if needed
            let ret = bpf_update_elem(
                self.offsets_map_fd,
                &pid as *const u32 as *const libc::c_void,
                &runtime_info.offsets as *const PHPOffsets as *const libc::c_void,
                BPF_ANY,
            );

            if ret != 0 {
                return Err(
                    format!("Failed to store PHP offsets for process {}: {}", pid, ret).into(),
                );
            }

            Ok(())
        }
    }
}

/// Performance statistics for PHP unwinding
#[derive(Debug, Clone)]
pub struct PHPUnwindStats {
    pub detection_count: u64,
    pub success_count: u64,
    pub error_count: u64,
    pub manager_stats: crate::unwind::version_manager::VersionManagerStats,
}

impl PHPUnwindStats {
    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        if self.detection_count == 0 {
            0.0
        } else {
            self.success_count as f64 / self.detection_count as f64
        }
    }

    /// Calculate error rate
    pub fn error_rate(&self) -> f64 {
        if self.detection_count == 0 {
            0.0
        } else {
            self.error_count as f64 / self.detection_count as f64
        }
    }
}

/// Legacy compatibility extensions for PHPVersion
impl PHPVersion {
    /// Convert to u32 format used by BPF maps
    pub fn to_u32(&self) -> u32 {
        ((self.major as u32) << 16) | ((self.minor as u32) << 8) | (self.patch as u32)
    }

    /// Create from u32 format used by BPF maps
    pub fn from_u32(version: u32) -> Self {
        Self {
            major: ((version >> 16) & 0xFF) as u8,
            minor: ((version >> 8) & 0xFF) as u8,
            patch: (version & 0xFF) as u8,
        }
    }
}

/// Backward compatibility type alias
pub type PHPUnwindTable = ModernizedPHPUnwindTable;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_php_sapi_detection() {
        assert_eq!(PHPSapi::from("php-fpm"), PHPSapi::FPM);
        assert_eq!(PHPSapi::from("cli"), PHPSapi::CLI);
        assert_eq!(PHPSapi::from("apache2"), PHPSapi::Apache);
        assert_eq!(PHPSapi::from("unknown"), PHPSapi::Unknown);
    }

    #[test]
    fn test_php_version_conversion() {
        let version = PHPVersion::new(8, 2, 5);
        let version_u32 = version.to_u32();
        assert_eq!(version_u32, 0x00080205);

        let recovered = PHPVersion::from_u32(version_u32);
        assert_eq!(recovered, version);
    }

    #[test]
    fn test_stats_calculation() {
        let stats = PHPUnwindStats {
            detection_count: 100,
            success_count: 85,
            error_count: 15,
            manager_stats: Default::default(),
        };

        assert_eq!(stats.success_rate(), 0.85);
        assert_eq!(stats.error_rate(), 0.15);
    }
}
