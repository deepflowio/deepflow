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

//! Security management for eBPF profiler
//!
//! This module provides security configuration, memory layout management,
//! and access control for the eBPF-based profiling system.

use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Result as IoResult};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::unwind::{
    constants::profiler::*,
    monitoring::{ProfilerError, ProfilerMetrics, ProfilerResult},
};

/// Security levels for memory validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Basic = 1,
    Enhanced = 2,
    Paranoid = 3,
}

impl From<u8> for SecurityLevel {
    fn from(value: u8) -> Self {
        match value {
            1 => SecurityLevel::Basic,
            2 => SecurityLevel::Enhanced,
            3 => SecurityLevel::Paranoid,
            _ => SecurityLevel::Enhanced, // Default to enhanced
        }
    }
}

/// Memory region types for validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionType {
    Unknown = 0,
    Executable = 1,
    Heap = 2,
    Stack = 3,
    Shared = 4,
    Vdso = 5,
}

/// Process memory layout information
#[derive(Debug, Clone)]
pub struct ProcessMemoryLayout {
    pub pid: u32,
    pub stack_start: u64,
    pub stack_end: u64,
    pub heap_start: u64,
    pub heap_end: u64,
    pub code_start: u64,
    pub code_end: u64,
    pub shared_libs: Vec<MemoryRegion>,
    pub last_updated: Instant,
}

/// Memory region descriptor
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub path: String,
    pub region_type: MemoryRegionType,
}

impl MemoryRegion {
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address < self.end
    }

    pub fn size(&self) -> u64 {
        self.end - self.start
    }
}

/// Memory access statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct MemoryAccessStats {
    pub total_attempts: u64,
    pub successful_reads: u64,
    pub failed_reads: u64,
    pub invalid_addresses: u64,
    pub boundary_violations: u64,
    pub alignment_errors: u64,
    pub rate_limit_hits: u64,
    pub last_violation_time: Option<Instant>,
}

impl MemoryAccessStats {
    pub fn success_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            return 100.0;
        }
        (self.successful_reads as f64 / self.total_attempts as f64) * 100.0
    }

    pub fn failure_rate(&self) -> f64 {
        100.0 - self.success_rate()
    }
}

/// Security configuration for the profiler
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub security_level: SecurityLevel,
    pub enable_rate_limiting: bool,
    pub max_access_rate_per_second: u64,
    pub max_failure_rate_percent: f64,
    pub memory_layout_cache_ttl: Duration,
    pub enable_memory_layout_validation: bool,
    pub max_string_read_size: u32,
    pub max_batch_size: u32,
    pub enable_abuse_detection: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::Enhanced,
            enable_rate_limiting: true,
            max_access_rate_per_second: 1000,
            max_failure_rate_percent: 50.0,
            memory_layout_cache_ttl: Duration::from_secs(300), // 5 minutes
            enable_memory_layout_validation: true,
            max_string_read_size: 256,
            max_batch_size: 32,
            enable_abuse_detection: true,
        }
    }
}

/// Security manager for eBPF profiler
pub struct SecurityManager {
    config: SecurityConfig,
    memory_layouts: Arc<Mutex<HashMap<u32, ProcessMemoryLayout>>>,
    access_stats: Arc<Mutex<HashMap<u32, MemoryAccessStats>>>,
    metrics: Arc<ProfilerMetrics>,
    last_cleanup: Mutex<Instant>,
}

impl SecurityManager {
    pub fn new(config: SecurityConfig, metrics: Arc<ProfilerMetrics>) -> Self {
        Self {
            config,
            memory_layouts: Arc::new(Mutex::new(HashMap::new())),
            access_stats: Arc::new(Mutex::new(HashMap::new())),
            metrics,
            last_cleanup: Mutex::new(Instant::now()),
        }
    }

    /// Parse process memory layout from /proc/[pid]/maps
    pub fn update_process_memory_layout(&self, pid: u32) -> ProfilerResult<()> {
        let maps_path = format!("/proc/{}/maps", pid);
        let layout = self.parse_proc_maps(&maps_path, pid)?;

        {
            let mut layouts = self.memory_layouts.lock().unwrap();
            layouts.insert(pid, layout);
        }

        debug!("Updated memory layout for process {}", pid);
        Ok(())
    }

    /// Parse /proc/[pid]/maps file
    fn parse_proc_maps(&self, path: &str, pid: u32) -> ProfilerResult<ProcessMemoryLayout> {
        let file = File::open(path).map_err(|e| ProfilerError::InvalidMemoryAccess {
            address: 0,
            size: 0,
            context: format!("Failed to open {}: {}", path, e),
        })?;

        let reader = BufReader::new(file);
        let mut layout = ProcessMemoryLayout {
            pid,
            stack_start: 0,
            stack_end: 0,
            heap_start: 0,
            heap_end: 0,
            code_start: 0,
            code_end: 0,
            shared_libs: Vec::new(),
            last_updated: Instant::now(),
        };

        for line in reader.lines() {
            let line = line.map_err(|e| ProfilerError::InvalidMemoryAccess {
                address: 0,
                size: 0,
                context: format!("Failed to read maps line: {}", e),
            })?;

            if let Some(region) = self.parse_maps_line(&line)? {
                self.categorize_memory_region(&mut layout, region);
            }
        }

        // Validate the parsed layout
        self.validate_memory_layout(&layout)?;

        Ok(layout)
    }

    /// Parse a single line from /proc/[pid]/maps
    fn parse_maps_line(&self, line: &str) -> ProfilerResult<Option<MemoryRegion>> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return Ok(None); // Skip invalid lines
        }

        // Parse address range
        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            return Ok(None);
        }

        let start = u64::from_str_radix(addr_parts[0], 16).map_err(|_| {
            ProfilerError::InvalidMemoryAccess {
                address: 0,
                size: 0,
                context: format!("Invalid start address: {}", addr_parts[0]),
            }
        })?;

        let end = u64::from_str_radix(addr_parts[1], 16).map_err(|_| {
            ProfilerError::InvalidMemoryAccess {
                address: 0,
                size: 0,
                context: format!("Invalid end address: {}", addr_parts[1]),
            }
        })?;

        let permissions = parts[1].to_string();
        let path = if parts.len() > 5 {
            parts[5].to_string()
        } else {
            String::new()
        };

        let region_type = self.determine_region_type(&path, &permissions);

        Ok(Some(MemoryRegion {
            start,
            end,
            permissions,
            path,
            region_type,
        }))
    }

    /// Determine memory region type based on path and permissions
    fn determine_region_type(&self, path: &str, permissions: &str) -> MemoryRegionType {
        if path.contains("[stack]") {
            MemoryRegionType::Stack
        } else if path.contains("[heap]") {
            MemoryRegionType::Heap
        } else if path.contains("[vdso]") {
            MemoryRegionType::Vdso
        } else if permissions.contains('x') && !path.is_empty() {
            MemoryRegionType::Executable
        } else if !path.is_empty() {
            MemoryRegionType::Shared
        } else {
            MemoryRegionType::Unknown
        }
    }

    /// Categorize memory region into layout structure
    fn categorize_memory_region(&self, layout: &mut ProcessMemoryLayout, region: MemoryRegion) {
        match region.region_type {
            MemoryRegionType::Stack => {
                layout.stack_start = region.start;
                layout.stack_end = region.end;
            }
            MemoryRegionType::Heap => {
                layout.heap_start = region.start;
                layout.heap_end = region.end;
            }
            MemoryRegionType::Executable => {
                if layout.code_start == 0 || region.start < layout.code_start {
                    layout.code_start = region.start;
                }
                if region.end > layout.code_end {
                    layout.code_end = region.end;
                }
                layout.shared_libs.push(region);
            }
            _ => {
                layout.shared_libs.push(region);
            }
        }
    }

    /// Validate memory layout for consistency
    fn validate_memory_layout(&self, layout: &ProcessMemoryLayout) -> ProfilerResult<()> {
        // Basic sanity checks
        if layout.stack_start >= layout.stack_end && layout.stack_start != 0 {
            return Err(ProfilerError::InvalidMemoryAccess {
                address: layout.stack_start,
                size: 0,
                context: "Invalid stack region".to_string(),
            });
        }

        if layout.heap_start >= layout.heap_end && layout.heap_start != 0 {
            return Err(ProfilerError::InvalidMemoryAccess {
                address: layout.heap_start,
                size: 0,
                context: "Invalid heap region".to_string(),
            });
        }

        if layout.code_start >= layout.code_end && layout.code_start != 0 {
            return Err(ProfilerError::InvalidMemoryAccess {
                address: layout.code_start,
                size: 0,
                context: "Invalid code region".to_string(),
            });
        }

        Ok(())
    }

    /// Validate memory access attempt
    pub fn validate_memory_access(
        &self,
        pid: u32,
        address: u64,
        size: usize,
        region_type: MemoryRegionType,
    ) -> ProfilerResult<()> {
        // Check rate limiting first
        if self.config.enable_rate_limiting {
            self.check_access_rate_limit(pid)?;
        }

        // Basic address validation
        if address == 0 || size == 0 {
            self.record_access_failure(pid, "null_pointer_or_zero_size");
            return Err(ProfilerError::InvalidMemoryAccess {
                address,
                size,
                context: "Null pointer or zero size".to_string(),
            });
        }

        // Check for integer overflow
        if address.saturating_add(size as u64) < address {
            self.record_access_failure(pid, "integer_overflow");
            return Err(ProfilerError::InvalidMemoryAccess {
                address,
                size,
                context: "Address + size overflow".to_string(),
            });
        }

        // Alignment check for 64-bit systems
        if address % 8 != 0 {
            self.record_access_failure(pid, "alignment_error");
            return Err(ProfilerError::InvalidMemoryAccess {
                address,
                size,
                context: "Address not 8-byte aligned".to_string(),
            });
        }

        // Memory layout validation (if enabled)
        if self.config.enable_memory_layout_validation {
            self.validate_against_memory_layout(pid, address, size, region_type)?;
        }

        // Record successful validation
        self.record_access_success(pid);
        Ok(())
    }

    /// Validate against known memory layout
    fn validate_against_memory_layout(
        &self,
        pid: u32,
        address: u64,
        size: usize,
        expected_region: MemoryRegionType,
    ) -> ProfilerResult<()> {
        let layouts = self.memory_layouts.lock().unwrap();
        let layout = layouts.get(&pid);

        if let Some(layout) = layout {
            // Check if address is in expected region
            let end_address = address + size as u64;

            let is_valid = match expected_region {
                MemoryRegionType::Stack => {
                    address >= layout.stack_start && end_address <= layout.stack_end
                }
                MemoryRegionType::Heap => {
                    address >= layout.heap_start && end_address <= layout.heap_end
                }
                MemoryRegionType::Executable => {
                    (address >= layout.code_start && end_address <= layout.code_end)
                        || layout.shared_libs.iter().any(|region| {
                            region.region_type == MemoryRegionType::Executable
                                && region.contains(address)
                                && end_address <= region.end
                        })
                }
                _ => {
                    // For other types, just check it's in a valid region
                    layout.shared_libs.iter().any(|region| {
                        region.contains(address) && end_address <= region.end
                    })
                }
            };

            if !is_valid {
                self.record_access_failure(pid, "region_boundary_violation");
                return Err(ProfilerError::InvalidMemoryAccess {
                    address,
                    size,
                    context: format!("Address not in expected {:?} region", expected_region),
                });
            }
        }
        // If no layout is cached, allow access (basic validation only)

        Ok(())
    }

    /// Check access rate limiting
    fn check_access_rate_limit(&self, pid: u32) -> ProfilerResult<()> {
        let mut stats_map = self.access_stats.lock().unwrap();
        let stats = stats_map.entry(pid).or_default();

        stats.total_attempts += 1;

        // Check failure rate
        if stats.total_attempts > 50 && stats.failure_rate() > self.config.max_failure_rate_percent
        {
            self.record_access_failure(pid, "high_failure_rate");
            return Err(ProfilerError::InvalidMemoryAccess {
                address: 0,
                size: 0,
                context: format!(
                    "High failure rate: {:.1}% > {:.1}%",
                    stats.failure_rate(),
                    self.config.max_failure_rate_percent
                ),
            });
        }

        // Simple rate limiting: check recent access rate
        if let Some(last_violation) = stats.last_violation_time {
            if last_violation.elapsed() < Duration::from_secs(1)
                && stats.total_attempts % 100 == 0
                && stats.total_attempts > self.config.max_access_rate_per_second
            {
                stats.rate_limit_hits += 1;
                return Err(ProfilerError::InvalidMemoryAccess {
                    address: 0,
                    size: 0,
                    context: "Rate limit exceeded".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Record successful memory access
    fn record_access_success(&self, pid: u32) {
        let mut stats_map = self.access_stats.lock().unwrap();
        let stats = stats_map.entry(pid).or_default();
        stats.successful_reads += 1;
    }

    /// Record failed memory access
    fn record_access_failure(&self, pid: u32, reason: &str) {
        let mut stats_map = self.access_stats.lock().unwrap();
        let stats = stats_map.entry(pid).or_default();
        stats.failed_reads += 1;
        stats.last_violation_time = Some(Instant::now());

        match reason {
            "null_pointer_or_zero_size" | "integer_overflow" => {
                stats.invalid_addresses += 1;
            }
            "alignment_error" => {
                stats.alignment_errors += 1;
            }
            "region_boundary_violation" => {
                stats.boundary_violations += 1;
            }
            "high_failure_rate" => {
                stats.rate_limit_hits += 1;
            }
            _ => {}
        }

        self.metrics.record_memory_access(false);
    }

    /// Get memory access statistics for a process
    pub fn get_access_stats(&self, pid: u32) -> Option<MemoryAccessStats> {
        let stats_map = self.access_stats.lock().unwrap();
        stats_map.get(&pid).cloned()
    }

    /// Get security summary for all processes
    pub fn get_security_summary(&self) -> SecuritySummary {
        let stats_map = self.access_stats.lock().unwrap();
        let layouts_map = self.memory_layouts.lock().unwrap();

        let mut total_attempts = 0;
        let mut total_failures = 0;
        let mut processes_with_violations = 0;

        for stats in stats_map.values() {
            total_attempts += stats.total_attempts;
            total_failures += stats.failed_reads;
            if stats.failed_reads > 0 {
                processes_with_violations += 1;
            }
        }

        SecuritySummary {
            security_level: self.config.security_level,
            tracked_processes: stats_map.len() as u32,
            processes_with_layouts: layouts_map.len() as u32,
            total_memory_attempts: total_attempts,
            total_memory_failures: total_failures,
            processes_with_violations,
            overall_success_rate: if total_attempts > 0 {
                ((total_attempts - total_failures) as f64 / total_attempts as f64) * 100.0
            } else {
                100.0
            },
        }
    }

    /// Cleanup expired entries
    pub fn cleanup_expired_entries(&self) {
        let mut last_cleanup = self.last_cleanup.lock().unwrap();
        if last_cleanup.elapsed() < Duration::from_secs(60) {
            return; // Cleanup at most once per minute
        }

        let cutoff = Instant::now() - self.config.memory_layout_cache_ttl;

        {
            let mut layouts = self.memory_layouts.lock().unwrap();
            layouts.retain(|_, layout| layout.last_updated > cutoff);
        }

        // Also cleanup old access stats
        {
            let mut stats = self.access_stats.lock().unwrap();
            stats.retain(|_, stat| {
                stat.last_violation_time
                    .map_or(true, |time| time > cutoff)
            });
        }

        *last_cleanup = Instant::now();
        debug!("Cleaned up expired security entries");
    }

    /// Remove process from tracking
    pub fn remove_process(&self, pid: u32) {
        {
            let mut layouts = self.memory_layouts.lock().unwrap();
            layouts.remove(&pid);
        }
        {
            let mut stats = self.access_stats.lock().unwrap();
            stats.remove(&pid);
        }
        debug!("Removed security tracking for process {}", pid);
    }
}

/// Security summary for monitoring
#[derive(Debug, Clone)]
pub struct SecuritySummary {
    pub security_level: SecurityLevel,
    pub tracked_processes: u32,
    pub processes_with_layouts: u32,
    pub total_memory_attempts: u64,
    pub total_memory_failures: u64,
    pub processes_with_violations: u32,
    pub overall_success_rate: f64,
}

impl SecuritySummary {
    pub fn is_healthy(&self) -> bool {
        self.overall_success_rate > 90.0 && self.processes_with_violations < self.tracked_processes / 4
    }
}