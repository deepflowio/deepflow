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

//! Version detection and offset management
//!
//! This module provides comprehensive version detection for PHP and Node.js/V8,
//! and manages the mapping between versions and their corresponding structure offsets.

use crate::unwind::{
    cache::BoundedLruCache, php_offsets::get_php_offsets, runtime_detector::RuntimeDetector,
    v8_offsets::get_v8_offsets, version_specific_offsets::*,
};

use std::time::Duration;

/// Version-specific offset manager
pub struct VersionSpecificOffsetManager {
    // Runtime detector for low-level operations
    runtime_detector: std::sync::Mutex<RuntimeDetector>,

    // Caches for detected versions to avoid repeated detection
    php_version_cache: BoundedLruCache<u32, PHPVersion>,
    nodejs_version_cache: BoundedLruCache<u32, NodeJSVersion>,

    // Statistics
    php_detection_count: std::sync::atomic::AtomicU64,
    nodejs_detection_count: std::sync::atomic::AtomicU64,
}

impl VersionSpecificOffsetManager {
    /// Create a new version-specific offset manager
    pub fn new() -> Self {
        Self {
            runtime_detector: std::sync::Mutex::new(RuntimeDetector::new()),
            php_version_cache: BoundedLruCache::new(1024, Duration::from_secs(300)), // 5min TTL
            nodejs_version_cache: BoundedLruCache::new(1024, Duration::from_secs(300)),
            php_detection_count: std::sync::atomic::AtomicU64::new(0),
            nodejs_detection_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Detect PHP version and get corresponding offsets
    pub fn detect_php_runtime(&self, pid: u32) -> Result<PHPRuntimeInfo> {
        self.php_detection_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Check cache first
        if let Some(version) = self.php_version_cache.get(&pid) {
            if let Some(offsets) = get_php_offsets(&version) {
                let mut detector = self.runtime_detector.lock().unwrap();
                if let Some(eg_address) = detector.find_php_executor_globals(pid)? {
                    return Ok(PHPRuntimeInfo {
                        version,
                        executor_globals_address: eg_address,
                        offsets,
                    });
                }
            }
        }

        // Perform fresh detection
        let mut detector = self.runtime_detector.lock().unwrap();
        let version = detector
            .detect_php_process(pid)?
            .ok_or_else(|| VersionOffsetError::VersionDetectionFailed(pid))?;

        let offsets = get_php_offsets(&version)
            .ok_or_else(|| VersionOffsetError::UnsupportedPHPVersion(version))?;

        let eg_address = detector
            .find_php_executor_globals(pid)?
            .ok_or_else(|| VersionOffsetError::VersionDetectionFailed(pid))?;

        // Validate offsets before caching
        detector.validate_php_offsets(pid, eg_address, offsets)?;

        // Cache the detected version
        let _ = self.php_version_cache.insert(pid, version);

        Ok(PHPRuntimeInfo {
            version,
            executor_globals_address: eg_address,
            offsets,
        })
    }

    /// Detect Node.js version and get corresponding V8 offsets
    pub fn detect_nodejs_runtime(&self, pid: u32) -> Result<NodeJSRuntimeInfo> {
        self.nodejs_detection_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Check cache first
        if let Some(nodejs_version) = self.nodejs_version_cache.get(&pid) {
            let v8_version = nodejs_version.to_v8_version();
            if let Some(offsets) = get_v8_offsets(&v8_version) {
                let mut detector = self.runtime_detector.lock().unwrap();
                if let Some(isolate_address) = detector.find_nodejs_isolate(pid)? {
                    return Ok(NodeJSRuntimeInfo {
                        node_version: nodejs_version,
                        v8_version,
                        isolate_address,
                        offsets,
                    });
                }
            }
        }

        // Perform fresh detection
        let mut detector = self.runtime_detector.lock().unwrap();
        let nodejs_version = detector
            .detect_nodejs_process(pid)?
            .ok_or_else(|| VersionOffsetError::VersionDetectionFailed(pid))?;

        let v8_version = nodejs_version.to_v8_version();
        let offsets = get_v8_offsets(&v8_version)
            .ok_or_else(|| VersionOffsetError::UnsupportedV8Version(v8_version))?;

        let isolate_address = detector
            .find_nodejs_isolate(pid)?
            .ok_or_else(|| VersionOffsetError::VersionDetectionFailed(pid))?;

        // Validate offsets before caching
        detector.validate_v8_offsets(pid, isolate_address, offsets)?;

        // Cache the detected version
        let _ = self.nodejs_version_cache.insert(pid, nodejs_version);

        Ok(NodeJSRuntimeInfo {
            node_version: nodejs_version,
            v8_version,
            isolate_address,
            offsets,
        })
    }

    /// Clear caches for a specific process (called when process exits)
    pub fn clear_process_cache(&self, pid: u32) {
        let _ = self.php_version_cache.remove(&pid);
        let _ = self.nodejs_version_cache.remove(&pid);

        // Clear runtime detector cache as well
        if let Ok(mut detector) = self.runtime_detector.lock() {
            detector.clear_process_cache(pid);
        }
    }

    /// Get manager statistics
    pub fn get_stats(&self) -> VersionManagerStats {
        VersionManagerStats {
            php_detection_count: self
                .php_detection_count
                .load(std::sync::atomic::Ordering::Relaxed),
            nodejs_detection_count: self
                .nodejs_detection_count
                .load(std::sync::atomic::Ordering::Relaxed),
            php_cache_stats: self.php_version_cache.stats().unwrap_or_default(),
            nodejs_cache_stats: self.nodejs_version_cache.stats().unwrap_or_default(),
        }
    }
}

/// PHP version detection implementation - delegated to RuntimeDetector
impl VersionSpecificOffsetManager {
    // PHP version detection is now handled by RuntimeDetector
}

/// Node.js version detection implementation - delegated to RuntimeDetector
impl VersionSpecificOffsetManager {
    // Node.js version detection is now handled by RuntimeDetector
}

/// Validation implementation - delegated to RuntimeDetector
impl VersionSpecificOffsetManager {
    // Validation is now handled by RuntimeDetector
}

/// Statistics for version manager
#[derive(Debug, Clone, Default)]
pub struct VersionManagerStats {
    pub php_detection_count: u64,
    pub nodejs_detection_count: u64,
    pub php_cache_stats: crate::unwind::cache::CacheStats,
    pub nodejs_cache_stats: crate::unwind::cache::CacheStats,
}

// Helper functions are now implemented in RuntimeDetector
