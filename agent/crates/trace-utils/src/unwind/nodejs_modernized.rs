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

//! Modernized Node.js/V8 stack unwinding with unified version-specific offsets
//!
//! This module replaces the hardcoded V8 offset approach with the new
//! VersionSpecificOffsetManager system for better maintainability and accuracy.

use crate::unwind::version_manager::VersionSpecificOffsetManager;
use crate::unwind::version_specific_offsets::*;
use log::{debug, trace, warn};
use std::sync::Arc;

use crate::error::Result;
use crate::utils::{bpf_update_elem, BPF_ANY};

/// Node.js runtime environment types
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum NodeJSEnvironment {
    Unknown = 0,
    Standalone = 1, // node script.js
    NPM = 2,        // npm run script
    Yarn = 3,       // yarn run script
    PM2 = 4,        // PM2 process manager
    Forever = 5,    // Forever process manager
    Docker = 6,     // Dockerized Node.js
    Kubernetes = 7, // Kubernetes pod
}

impl From<&str> for NodeJSEnvironment {
    fn from(cmdline: &str) -> Self {
        let cmdline_lower = cmdline.to_lowercase();

        if cmdline_lower.contains("pm2") {
            NodeJSEnvironment::PM2
        } else if cmdline_lower.contains("forever") {
            NodeJSEnvironment::Forever
        } else if cmdline_lower.contains("npm") {
            NodeJSEnvironment::NPM
        } else if cmdline_lower.contains("yarn") {
            NodeJSEnvironment::Yarn
        } else if cmdline_lower.contains("docker") || std::path::Path::new("/.dockerenv").exists() {
            NodeJSEnvironment::Docker
        } else if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
            NodeJSEnvironment::Kubernetes
        } else {
            NodeJSEnvironment::Standalone
        }
    }
}

/// Node.js runtime information for BPF maps
#[derive(Debug, Clone)]
#[repr(C)]
pub struct NodeJSRuntimeInfo {
    pub node_version: u32,
    pub v8_version: u32,
    pub environment: NodeJSEnvironment,
    pub isolate_addr: u64,
    pub offsets: V8Offsets,
}

/// Modernized Node.js stack unwinding table
/// Uses the new unified version-specific offset system
pub struct ModernizedNodeJSUnwindTable {
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

impl ModernizedNodeJSUnwindTable {
    /// Create a new modernized Node.js unwind table
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

    /// Add a Node.js process to the unwind table
    /// Uses the new version-specific offset detection system
    pub fn add_process(&mut self, pid: u32) -> Result<()> {
        self.detection_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        trace!("Adding Node.js process {} to unwind table", pid);

        // Use the new offset manager to detect Node.js runtime
        match self.offset_manager.detect_nodejs_runtime(pid) {
            Ok(runtime_info) => {
                debug!(
                    "Detected Node.js {} (V8 {}) for process {} with isolate at 0x{:x}",
                    runtime_info.node_version,
                    runtime_info.v8_version,
                    pid,
                    runtime_info.isolate_address
                );

                // Convert to BPF-compatible format
                let bpf_runtime_info = NodeJSRuntimeInfo {
                    node_version: runtime_info.node_version.to_u32(),
                    v8_version: runtime_info.v8_version.to_u32(),
                    environment: self.detect_environment(pid),
                    isolate_addr: runtime_info.isolate_address,
                    offsets: *runtime_info.offsets,
                };

                // Store in BPF maps
                self.store_runtime_info(pid, &bpf_runtime_info)?;

                self.success_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                warn!(
                    "Failed to detect Node.js runtime for process {}: {}",
                    pid, e
                );
                self.error_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(format!("{}", e).into())
            }
        }
    }

    /// Remove a Node.js process from the unwind table
    pub fn remove_process(&mut self, pid: u32) {
        trace!("Removing Node.js process {} from unwind table", pid);

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
    pub fn get_stats(&self) -> NodeJSUnwindStats {
        NodeJSUnwindStats {
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

    /// Detect Node.js runtime environment from process information
    fn detect_environment(&self, pid: u32) -> NodeJSEnvironment {
        // Try to read command line
        if let Ok(cmdline) = std::fs::read_to_string(format!("/proc/{}/cmdline", pid)) {
            return NodeJSEnvironment::from(cmdline.as_str());
        }

        // Try to read environment variables
        if let Ok(environ) = std::fs::read_to_string(format!("/proc/{}/environ", pid)) {
            return NodeJSEnvironment::from(environ.as_str());
        }

        NodeJSEnvironment::Unknown
    }

    /// Store runtime information in BPF maps
    fn store_runtime_info(&self, pid: u32, runtime_info: &NodeJSRuntimeInfo) -> Result<()> {
        unsafe {
            // Store runtime info
            let ret = bpf_update_elem(
                self.runtime_info_map_fd,
                &pid as *const u32 as *const libc::c_void,
                runtime_info as *const NodeJSRuntimeInfo as *const libc::c_void,
                BPF_ANY,
            );

            if ret != 0 {
                return Err(format!(
                    "Failed to store Node.js runtime info for process {}: {}",
                    pid, ret
                )
                .into());
            }

            // Store V8 offsets separately if needed
            let ret = bpf_update_elem(
                self.offsets_map_fd,
                &pid as *const u32 as *const libc::c_void,
                &runtime_info.offsets as *const V8Offsets as *const libc::c_void,
                BPF_ANY,
            );

            if ret != 0 {
                return Err(
                    format!("Failed to store V8 offsets for process {}: {}", pid, ret).into(),
                );
            }

            Ok(())
        }
    }
}

/// Performance statistics for Node.js unwinding
#[derive(Debug, Clone)]
pub struct NodeJSUnwindStats {
    pub detection_count: u64,
    pub success_count: u64,
    pub error_count: u64,
    pub manager_stats: crate::unwind::version_manager::VersionManagerStats,
}

impl NodeJSUnwindStats {
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

/// Legacy compatibility extensions for NodeJSVersion
impl NodeJSVersion {
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

/// Legacy compatibility extensions for V8Version
impl V8Version {
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
pub type NodeJSUnwindTable = ModernizedNodeJSUnwindTable;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nodejs_environment_detection() {
        assert_eq!(
            NodeJSEnvironment::from("node server.js"),
            NodeJSEnvironment::Standalone
        );
        assert_eq!(
            NodeJSEnvironment::from("npm run start"),
            NodeJSEnvironment::NPM
        );
        assert_eq!(
            NodeJSEnvironment::from("pm2 start app.js"),
            NodeJSEnvironment::PM2
        );
        assert_eq!(NodeJSEnvironment::from("yarn dev"), NodeJSEnvironment::Yarn);
    }

    #[test]
    fn test_version_conversion() {
        let node_version = NodeJSVersion::new(20, 10, 0);
        let version_u32 = node_version.to_u32();
        assert_eq!(version_u32, 0x00140A00);

        let recovered = NodeJSVersion::from_u32(version_u32);
        assert_eq!(recovered, node_version);

        let v8_version = V8Version::new(11, 8, 0);
        let v8_u32 = v8_version.to_u32();
        assert_eq!(v8_u32, 0x000B0800);

        let v8_recovered = V8Version::from_u32(v8_u32);
        assert_eq!(v8_recovered, v8_version);
    }

    #[test]
    fn test_nodejs_to_v8_mapping() {
        let node20 = NodeJSVersion::new(20, 5, 0);
        let v8_version = node20.to_v8_version();
        assert_eq!(v8_version.major, 11);
        assert_eq!(v8_version.minor, 5);
    }

    #[test]
    fn test_stats_calculation() {
        let stats = NodeJSUnwindStats {
            detection_count: 200,
            success_count: 180,
            error_count: 20,
            manager_stats: Default::default(),
        };

        assert_eq!(stats.success_rate(), 0.9);
        assert_eq!(stats.error_rate(), 0.1);
    }
}
