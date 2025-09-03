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

//! Enhanced version compatibility detection and management
//!
//! This module provides comprehensive version compatibility checking for
//! different runtime environments, with detailed error reporting and
//! automatic fallback mechanisms.

use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::unwind::{
    monitoring::{ProfilerError, ProfilerMetrics, ProfilerResult},
    symbol_resolver::RuntimeType,
    version_specific_offsets::*,
};

/// Version compatibility status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatibilityStatus {
    FullySupported,
    PartiallySupportedWithWarnings,
    Unsupported,
    Unknown,
}

/// Compatibility issue severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    Info = 0,
    Warning = 1,
    Error = 2,
    Critical = 3,
}

/// Version compatibility issue
#[derive(Debug, Clone)]
pub struct CompatibilityIssue {
    pub severity: IssueSeverity,
    pub message: String,
    pub recommendation: Option<String>,
    pub runtime_type: RuntimeType,
    pub detected_version: String,
    pub minimum_supported: Option<String>,
    pub maximum_supported: Option<String>,
}

/// Version detection result
#[derive(Debug, Clone)]
pub struct VersionDetectionResult {
    pub runtime_type: RuntimeType,
    pub detected_version: String,
    pub compatibility_status: CompatibilityStatus,
    pub issues: Vec<CompatibilityIssue>,
    pub offset_id: Option<u8>,
    pub confidence: f32, // 0.0 to 1.0
}

/// Process version information
#[derive(Debug, Clone)]
pub struct ProcessVersionInfo {
    pub pid: u32,
    pub runtime_type: RuntimeType,
    pub version: String,
    pub binary_path: String,
    pub command_line: String,
    pub compatibility_status: CompatibilityStatus,
    pub last_updated: Instant,
}

/// Version compatibility checker
pub struct VersionCompatibilityChecker {
    // Supported version ranges
    supported_php_versions: HashMap<(u8, u8), PHPVersion>,
    supported_nodejs_versions: HashMap<(u8, u8), NodeJSVersion>,
    supported_v8_versions: HashMap<(u8, u8), V8Version>,

    // Version patterns for detection
    php_version_regex: Regex,
    nodejs_version_regex: Regex,
    #[allow(dead_code)]
    v8_version_regex: Regex,

    // Process version cache
    process_versions: std::sync::Mutex<HashMap<u32, ProcessVersionInfo>>,

    // Metrics
    #[allow(dead_code)]
    metrics: Arc<ProfilerMetrics>,

    // Configuration
    max_cache_size: usize,
    cache_ttl: Duration,
}

impl VersionCompatibilityChecker {
    pub fn new(metrics: Arc<ProfilerMetrics>) -> ProfilerResult<Self> {
        let php_version_regex = Regex::new(r"PHP (\d+)\.(\d+)\.(\d+)").map_err(|e| {
            ProfilerError::ConfigurationError {
                parameter: "php_version_regex".to_string(),
                value: "PHP (\\d+)\\.(\\d+)\\.(\\d+)".to_string(),
                reason: e.to_string(),
            }
        })?;

        let nodejs_version_regex =
            Regex::new(r"v(\d+)\.(\d+)\.(\d+)").map_err(|e| ProfilerError::ConfigurationError {
                parameter: "nodejs_version_regex".to_string(),
                value: "v(\\d+)\\.(\\d+)\\.(\\d+)".to_string(),
                reason: e.to_string(),
            })?;

        let v8_version_regex = Regex::new(r"V8 (\d+)\.(\d+)\.(\d+)").map_err(|e| {
            ProfilerError::ConfigurationError {
                parameter: "v8_version_regex".to_string(),
                value: "V8 (\\d+)\\.(\\d+)\\.(\\d+)".to_string(),
                reason: e.to_string(),
            }
        })?;

        let mut checker = Self {
            supported_php_versions: HashMap::new(),
            supported_nodejs_versions: HashMap::new(),
            supported_v8_versions: HashMap::new(),
            php_version_regex,
            nodejs_version_regex,
            v8_version_regex,
            process_versions: std::sync::Mutex::new(HashMap::new()),
            metrics,
            max_cache_size: 1000,
            cache_ttl: Duration::from_secs(300), // 5 minutes
        };

        checker.initialize_supported_versions();
        Ok(checker)
    }

    /// Initialize the list of supported versions
    fn initialize_supported_versions(&mut self) {
        // PHP versions (7.4 - 8.2)
        self.supported_php_versions
            .insert((7, 4), PHPVersion::from_major_minor(7, 4));
        self.supported_php_versions
            .insert((8, 0), PHPVersion::from_major_minor(8, 0));
        self.supported_php_versions
            .insert((8, 1), PHPVersion::from_major_minor(8, 1));
        self.supported_php_versions
            .insert((8, 2), PHPVersion::from_major_minor(8, 2));

        // Node.js versions (16.x - 21.x)
        self.supported_nodejs_versions
            .insert((16, 0), NodeJSVersion::from_major_minor(16, 0));
        self.supported_nodejs_versions
            .insert((18, 0), NodeJSVersion::from_major_minor(18, 0));
        self.supported_nodejs_versions
            .insert((20, 0), NodeJSVersion::from_major_minor(20, 0));
        self.supported_nodejs_versions
            .insert((21, 0), NodeJSVersion::from_major_minor(21, 0));

        // V8 versions (corresponding to Node.js versions)
        self.supported_v8_versions
            .insert((9, 4), V8Version::from_major_minor(9, 4));
        self.supported_v8_versions
            .insert((10, 2), V8Version::from_major_minor(10, 2));
        self.supported_v8_versions
            .insert((11, 3), V8Version::from_major_minor(11, 3));
        self.supported_v8_versions
            .insert((11, 8), V8Version::from_major_minor(11, 8));
    }

    /// Detect and validate version compatibility for a process
    pub fn check_process_compatibility(&self, pid: u32) -> ProfilerResult<VersionDetectionResult> {
        // Check cache first
        {
            let cache = self.process_versions.lock().unwrap();
            if let Some(cached_info) = cache.get(&pid) {
                if cached_info.last_updated.elapsed() < self.cache_ttl {
                    return Ok(VersionDetectionResult {
                        runtime_type: cached_info.runtime_type,
                        detected_version: cached_info.version.clone(),
                        compatibility_status: cached_info.compatibility_status.clone(),
                        issues: self.get_compatibility_issues(&cached_info)?,
                        offset_id: self.get_offset_id(&cached_info),
                        confidence: 0.9, // High confidence for cached results
                    });
                }
            }
        }

        // Detect runtime type and version
        let runtime_type = self.detect_runtime_type(pid)?;
        let detection_result = match runtime_type {
            RuntimeType::PHP => self.detect_php_version(pid)?,
            RuntimeType::NodeJS => self.detect_nodejs_version(pid)?,
            RuntimeType::V8 => self.detect_v8_version(pid)?,
            RuntimeType::Python => self.detect_python_version(pid)?,
            _ => {
                return Ok(VersionDetectionResult {
                    runtime_type,
                    detected_version: "unknown".to_string(),
                    compatibility_status: CompatibilityStatus::Unknown,
                    issues: vec![],
                    offset_id: None,
                    confidence: 0.0,
                });
            }
        };

        // Cache the result
        self.cache_process_version(pid, &detection_result)?;

        Ok(detection_result)
    }

    /// Detect runtime type for a process
    fn detect_runtime_type(&self, pid: u32) -> ProfilerResult<RuntimeType> {
        let exe_path = self.get_process_executable(pid)?;
        let cmdline = self.get_process_cmdline(pid)?;

        // Check for PHP
        if exe_path.contains("php") || cmdline.contains("php") {
            return Ok(RuntimeType::PHP);
        }

        // Check for Node.js
        if exe_path.contains("node") || cmdline.contains("node") {
            return Ok(RuntimeType::NodeJS);
        }

        // Check for Python
        if exe_path.contains("python") || cmdline.contains("python") {
            return Ok(RuntimeType::Python);
        }

        Ok(RuntimeType::Unknown)
    }

    /// Detect PHP version and compatibility
    fn detect_php_version(&self, pid: u32) -> ProfilerResult<VersionDetectionResult> {
        let exe_path = self.get_process_executable(pid)?;

        // Try to get version from binary
        let version_output = Command::new(&exe_path)
            .arg("--version")
            .output()
            .map_err(|e| ProfilerError::RuntimeDetectionFailed {
                pid,
                reason: format!("Failed to execute PHP binary: {}", e),
                attempted_methods: vec!["php --version".to_string()],
            })?;

        let version_string = String::from_utf8_lossy(&version_output.stdout);

        if let Some(captures) = self.php_version_regex.captures(&version_string) {
            let major: u8 = captures[1].parse().unwrap_or(0);
            let minor: u8 = captures[2].parse().unwrap_or(0);
            let patch: u8 = captures[3].parse().unwrap_or(0);

            let version = format!("{}.{}.{}", major, minor, patch);
            let compatibility = self.check_php_compatibility(major, minor, patch);
            let issues = self.get_php_compatibility_issues(major, minor, patch);

            Ok(VersionDetectionResult {
                runtime_type: RuntimeType::PHP,
                detected_version: version,
                compatibility_status: compatibility,
                issues,
                offset_id: self.get_php_offset_id(major, minor),
                confidence: 0.95,
            })
        } else {
            // Try alternative detection methods
            self.detect_php_version_from_binary(pid, &exe_path)
        }
    }

    /// Detect Node.js version and compatibility
    fn detect_nodejs_version(&self, pid: u32) -> ProfilerResult<VersionDetectionResult> {
        let exe_path = self.get_process_executable(pid)?;

        // Try to get version from binary
        let version_output = Command::new(&exe_path)
            .arg("--version")
            .output()
            .map_err(|e| ProfilerError::RuntimeDetectionFailed {
                pid,
                reason: format!("Failed to execute Node.js binary: {}", e),
                attempted_methods: vec!["node --version".to_string()],
            })?;

        let version_string = String::from_utf8_lossy(&version_output.stdout);

        if let Some(captures) = self.nodejs_version_regex.captures(&version_string) {
            let major: u8 = captures[1].parse().unwrap_or(0);
            let minor: u8 = captures[2].parse().unwrap_or(0);
            let patch: u8 = captures[3].parse().unwrap_or(0);

            let version = format!("{}.{}.{}", major, minor, patch);
            let compatibility = self.check_nodejs_compatibility(major, minor, patch);
            let issues = self.get_nodejs_compatibility_issues(major, minor, patch);

            Ok(VersionDetectionResult {
                runtime_type: RuntimeType::NodeJS,
                detected_version: version,
                compatibility_status: compatibility,
                issues,
                offset_id: self.get_nodejs_offset_id(major, minor),
                confidence: 0.95,
            })
        } else {
            // Try alternative detection methods
            self.detect_nodejs_version_from_binary(pid, &exe_path)
        }
    }

    /// Detect V8 version (for Node.js processes)
    fn detect_v8_version(&self, pid: u32) -> ProfilerResult<VersionDetectionResult> {
        // V8 version detection is typically done in conjunction with Node.js
        // First detect Node.js version, then map to corresponding V8 version
        let nodejs_result = self.detect_nodejs_version(pid)?;

        if let Some(v8_version) = self.map_nodejs_to_v8_version(&nodejs_result.detected_version) {
            Ok(VersionDetectionResult {
                runtime_type: RuntimeType::V8,
                detected_version: v8_version,
                compatibility_status: nodejs_result.compatibility_status,
                issues: nodejs_result.issues,
                offset_id: nodejs_result.offset_id,
                confidence: nodejs_result.confidence * 0.9, // Slightly lower confidence for derived version
            })
        } else {
            Ok(VersionDetectionResult {
                runtime_type: RuntimeType::V8,
                detected_version: "unknown".to_string(),
                compatibility_status: CompatibilityStatus::Unknown,
                issues: vec![CompatibilityIssue {
                    severity: IssueSeverity::Warning,
                    message: "Unable to determine V8 version from Node.js version".to_string(),
                    recommendation: Some("Manual V8 version detection may be required".to_string()),
                    runtime_type: RuntimeType::V8,
                    detected_version: "unknown".to_string(),
                    minimum_supported: None,
                    maximum_supported: None,
                }],
                offset_id: None,
                confidence: 0.1,
            })
        }
    }

    /// Detect Python version (placeholder for future implementation)
    fn detect_python_version(&self, _pid: u32) -> ProfilerResult<VersionDetectionResult> {
        Ok(VersionDetectionResult {
            runtime_type: RuntimeType::Python,
            detected_version: "not implemented".to_string(),
            compatibility_status: CompatibilityStatus::Unsupported,
            issues: vec![CompatibilityIssue {
                severity: IssueSeverity::Info,
                message: "Python profiling support is planned for future release".to_string(),
                recommendation: Some("Use PHP or Node.js profiling for now".to_string()),
                runtime_type: RuntimeType::Python,
                detected_version: "unknown".to_string(),
                minimum_supported: None,
                maximum_supported: None,
            }],
            offset_id: None,
            confidence: 0.0,
        })
    }

    /// Check PHP version compatibility
    fn check_php_compatibility(&self, major: u8, minor: u8, _patch: u8) -> CompatibilityStatus {
        match (major, minor) {
            (7, 4) | (8, 0) | (8, 1) | (8, 2) => CompatibilityStatus::FullySupported,
            (7, 3) | (8, 3) => CompatibilityStatus::PartiallySupportedWithWarnings,
            _ => CompatibilityStatus::Unsupported,
        }
    }

    /// Check Node.js version compatibility
    fn check_nodejs_compatibility(&self, major: u8, _minor: u8, _patch: u8) -> CompatibilityStatus {
        match major {
            16 | 18 | 20 | 21 => CompatibilityStatus::FullySupported,
            14 | 22 => CompatibilityStatus::PartiallySupportedWithWarnings,
            _ => CompatibilityStatus::Unsupported,
        }
    }

    /// Get PHP compatibility issues
    fn get_php_compatibility_issues(
        &self,
        major: u8,
        minor: u8,
        patch: u8,
    ) -> Vec<CompatibilityIssue> {
        let mut issues = Vec::new();
        let version = format!("{}.{}.{}", major, minor, patch);

        match (major, minor) {
            (7, 4) | (8, 0) | (8, 1) | (8, 2) => {
                // Fully supported versions
                if patch < 5 {
                    issues.push(CompatibilityIssue {
                        severity: IssueSeverity::Warning,
                        message: format!("PHP {} patch version is quite old", version),
                        recommendation: Some(
                            "Consider updating to latest patch version".to_string(),
                        ),
                        runtime_type: RuntimeType::PHP,
                        detected_version: version.clone(),
                        minimum_supported: Some("7.4.5".to_string()),
                        maximum_supported: Some("8.2.x".to_string()),
                    });
                }
            }
            (7, 3) => {
                issues.push(CompatibilityIssue {
                    severity: IssueSeverity::Warning,
                    message: format!("PHP {} is approaching end-of-life", version),
                    recommendation: Some("Upgrade to PHP 7.4 or newer".to_string()),
                    runtime_type: RuntimeType::PHP,
                    detected_version: version.clone(),
                    minimum_supported: Some("7.4.0".to_string()),
                    maximum_supported: Some("8.2.x".to_string()),
                });
            }
            (8, 3) => {
                issues.push(CompatibilityIssue {
                    severity: IssueSeverity::Warning,
                    message: format!("PHP {} is a development version", version),
                    recommendation: Some("Use stable version for production".to_string()),
                    runtime_type: RuntimeType::PHP,
                    detected_version: version.clone(),
                    minimum_supported: Some("7.4.0".to_string()),
                    maximum_supported: Some("8.2.x".to_string()),
                });
            }
            _ => {
                issues.push(CompatibilityIssue {
                    severity: IssueSeverity::Error,
                    message: format!("PHP {} is not supported", version),
                    recommendation: Some("Upgrade to supported version (7.4 - 8.2)".to_string()),
                    runtime_type: RuntimeType::PHP,
                    detected_version: version.clone(),
                    minimum_supported: Some("7.4.0".to_string()),
                    maximum_supported: Some("8.2.x".to_string()),
                });
            }
        }

        issues
    }

    /// Get Node.js compatibility issues
    fn get_nodejs_compatibility_issues(
        &self,
        major: u8,
        minor: u8,
        patch: u8,
    ) -> Vec<CompatibilityIssue> {
        let mut issues = Vec::new();
        let version = format!("{}.{}.{}", major, minor, patch);

        match major {
            16 | 18 | 20 | 21 => {
                // Fully supported versions
                if minor == 0 && patch < 2 {
                    issues.push(CompatibilityIssue {
                        severity: IssueSeverity::Warning,
                        message: format!("Node.js {} is an early release", version),
                        recommendation: Some("Update to latest patch version".to_string()),
                        runtime_type: RuntimeType::NodeJS,
                        detected_version: version.clone(),
                        minimum_supported: Some("16.0.2".to_string()),
                        maximum_supported: Some("21.x.x".to_string()),
                    });
                }
            }
            14 => {
                issues.push(CompatibilityIssue {
                    severity: IssueSeverity::Warning,
                    message: format!("Node.js {} is reaching end-of-life", version),
                    recommendation: Some("Upgrade to Node.js 16 LTS or newer".to_string()),
                    runtime_type: RuntimeType::NodeJS,
                    detected_version: version.clone(),
                    minimum_supported: Some("16.0.0".to_string()),
                    maximum_supported: Some("21.x.x".to_string()),
                });
            }
            22 => {
                issues.push(CompatibilityIssue {
                    severity: IssueSeverity::Warning,
                    message: format!("Node.js {} is a current (non-LTS) version", version),
                    recommendation: Some("Consider using LTS version for production".to_string()),
                    runtime_type: RuntimeType::NodeJS,
                    detected_version: version.clone(),
                    minimum_supported: Some("16.0.0".to_string()),
                    maximum_supported: Some("21.x.x".to_string()),
                });
            }
            _ => {
                issues.push(CompatibilityIssue {
                    severity: IssueSeverity::Error,
                    message: format!("Node.js {} is not supported", version),
                    recommendation: Some("Use supported version (16.x - 21.x)".to_string()),
                    runtime_type: RuntimeType::NodeJS,
                    detected_version: version.clone(),
                    minimum_supported: Some("16.0.0".to_string()),
                    maximum_supported: Some("21.x.x".to_string()),
                });
            }
        }

        issues
    }

    /// Map Node.js version to corresponding V8 version
    fn map_nodejs_to_v8_version(&self, nodejs_version: &str) -> Option<String> {
        let parts: Vec<&str> = nodejs_version.split('.').collect();
        if parts.len() < 2 {
            return None;
        }

        let major: u8 = parts[0].parse().ok()?;
        let _minor: u8 = parts[1].parse().ok()?;

        // Approximate mapping based on Node.js versions
        match major {
            16 => Some("9.4.146".to_string()),
            18 => Some("10.2.154".to_string()),
            20 => Some("11.3.244".to_string()),
            21 => Some("11.8.172".to_string()),
            _ => None,
        }
    }

    /// Get offset ID for PHP version
    fn get_php_offset_id(&self, major: u8, minor: u8) -> Option<u8> {
        match (major, minor) {
            (7, 4) => Some(0),
            (8, 0) => Some(1),
            (8, 1) => Some(2),
            (8, 2) => Some(3),
            _ => None,
        }
    }

    /// Get offset ID for Node.js version
    fn get_nodejs_offset_id(&self, major: u8, _minor: u8) -> Option<u8> {
        match major {
            16 => Some(0),
            18 => Some(1),
            20 => Some(2),
            21 => Some(3),
            _ => None,
        }
    }

    /// Get process executable path
    fn get_process_executable(&self, pid: u32) -> ProfilerResult<String> {
        let exe_path = format!("/proc/{}/exe", pid);
        fs::read_link(&exe_path)
            .map_err(|e| ProfilerError::RuntimeDetectionFailed {
                pid,
                reason: format!("Failed to read executable path: {}", e),
                attempted_methods: vec![format!("readlink {}", exe_path)],
            })
            .map(|p| p.to_string_lossy().to_string())
    }

    /// Get process command line
    fn get_process_cmdline(&self, pid: u32) -> ProfilerResult<String> {
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        fs::read_to_string(&cmdline_path)
            .map_err(|e| ProfilerError::RuntimeDetectionFailed {
                pid,
                reason: format!("Failed to read command line: {}", e),
                attempted_methods: vec![format!("cat {}", cmdline_path)],
            })
            .map(|s| s.replace('\0', " "))
    }

    /// Alternative PHP version detection from binary analysis
    fn detect_php_version_from_binary(
        &self,
        _pid: u32,
        _exe_path: &str,
    ) -> ProfilerResult<VersionDetectionResult> {
        // This would involve binary analysis techniques
        // For now, return unknown with low confidence
        Ok(VersionDetectionResult {
            runtime_type: RuntimeType::PHP,
            detected_version: "unknown".to_string(),
            compatibility_status: CompatibilityStatus::Unknown,
            issues: vec![CompatibilityIssue {
                severity: IssueSeverity::Warning,
                message: "Unable to determine PHP version".to_string(),
                recommendation: Some("Ensure PHP binary is accessible and functional".to_string()),
                runtime_type: RuntimeType::PHP,
                detected_version: "unknown".to_string(),
                minimum_supported: Some("7.4.0".to_string()),
                maximum_supported: Some("8.2.x".to_string()),
            }],
            offset_id: None,
            confidence: 0.1,
        })
    }

    /// Alternative Node.js version detection from binary analysis
    fn detect_nodejs_version_from_binary(
        &self,
        _pid: u32,
        _exe_path: &str,
    ) -> ProfilerResult<VersionDetectionResult> {
        // This would involve binary analysis techniques
        // For now, return unknown with low confidence
        Ok(VersionDetectionResult {
            runtime_type: RuntimeType::NodeJS,
            detected_version: "unknown".to_string(),
            compatibility_status: CompatibilityStatus::Unknown,
            issues: vec![CompatibilityIssue {
                severity: IssueSeverity::Warning,
                message: "Unable to determine Node.js version".to_string(),
                recommendation: Some(
                    "Ensure Node.js binary is accessible and functional".to_string(),
                ),
                runtime_type: RuntimeType::NodeJS,
                detected_version: "unknown".to_string(),
                minimum_supported: Some("16.0.0".to_string()),
                maximum_supported: Some("21.x.x".to_string()),
            }],
            offset_id: None,
            confidence: 0.1,
        })
    }

    /// Cache process version information
    fn cache_process_version(
        &self,
        pid: u32,
        result: &VersionDetectionResult,
    ) -> ProfilerResult<()> {
        let mut cache = self.process_versions.lock().unwrap();

        // Cleanup old entries if cache is full
        if cache.len() >= self.max_cache_size {
            let cutoff = Instant::now() - self.cache_ttl;
            cache.retain(|_, info| info.last_updated > cutoff);

            // If still full, remove oldest entries
            if cache.len() >= self.max_cache_size {
                let to_remove: Vec<u32> = cache.keys().take(cache.len() / 4).copied().collect();
                for key in to_remove {
                    cache.remove(&key);
                }
            }
        }

        let exe_path = self.get_process_executable(pid).unwrap_or_default();
        let cmdline = self.get_process_cmdline(pid).unwrap_or_default();

        cache.insert(
            pid,
            ProcessVersionInfo {
                pid,
                runtime_type: result.runtime_type,
                version: result.detected_version.clone(),
                binary_path: exe_path,
                command_line: cmdline,
                compatibility_status: result.compatibility_status.clone(),
                last_updated: Instant::now(),
            },
        );

        Ok(())
    }

    /// Get compatibility issues for cached process info
    fn get_compatibility_issues(
        &self,
        info: &ProcessVersionInfo,
    ) -> ProfilerResult<Vec<CompatibilityIssue>> {
        // Parse version and generate issues based on runtime type
        let parts: Vec<&str> = info.version.split('.').collect();
        if parts.len() < 2 {
            return Ok(vec![]);
        }

        let major: u8 = parts[0].parse().unwrap_or(0);
        let minor: u8 = parts[1].parse().unwrap_or(0);
        let patch: u8 = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);

        match info.runtime_type {
            RuntimeType::PHP => Ok(self.get_php_compatibility_issues(major, minor, patch)),
            RuntimeType::NodeJS => Ok(self.get_nodejs_compatibility_issues(major, minor, patch)),
            _ => Ok(vec![]),
        }
    }

    /// Get offset ID for cached process info
    fn get_offset_id(&self, info: &ProcessVersionInfo) -> Option<u8> {
        let parts: Vec<&str> = info.version.split('.').collect();
        if parts.len() < 2 {
            return None;
        }

        let major: u8 = parts[0].parse().ok()?;
        let minor: u8 = parts[1].parse().ok()?;

        match info.runtime_type {
            RuntimeType::PHP => self.get_php_offset_id(major, minor),
            RuntimeType::NodeJS => self.get_nodejs_offset_id(major, minor),
            _ => None,
        }
    }

    /// Get compatibility summary for all tracked processes
    pub fn get_compatibility_summary(&self) -> CompatibilitySummary {
        let cache = self.process_versions.lock().unwrap();
        let mut summary = CompatibilitySummary::default();

        for info in cache.values() {
            summary.total_processes += 1;

            match info.runtime_type {
                RuntimeType::PHP => summary.php_processes += 1,
                RuntimeType::NodeJS => summary.nodejs_processes += 1,
                RuntimeType::Python => summary.python_processes += 1,
                _ => summary.other_processes += 1,
            }

            match info.compatibility_status {
                CompatibilityStatus::FullySupported => summary.fully_supported += 1,
                CompatibilityStatus::PartiallySupportedWithWarnings => {
                    summary.partially_supported += 1
                }
                CompatibilityStatus::Unsupported => summary.unsupported += 1,
                CompatibilityStatus::Unknown => summary.unknown += 1,
            }
        }

        summary
    }

    /// Remove process from tracking
    pub fn remove_process(&self, pid: u32) {
        let mut cache = self.process_versions.lock().unwrap();
        cache.remove(&pid);
    }

    /// Clear all cached version information
    pub fn clear_cache(&self) {
        let mut cache = self.process_versions.lock().unwrap();
        cache.clear();
    }
}

/// Compatibility summary for monitoring
#[derive(Debug, Clone, Default)]
pub struct CompatibilitySummary {
    pub total_processes: u32,
    pub php_processes: u32,
    pub nodejs_processes: u32,
    pub python_processes: u32,
    pub other_processes: u32,
    pub fully_supported: u32,
    pub partially_supported: u32,
    pub unsupported: u32,
    pub unknown: u32,
}

impl CompatibilitySummary {
    pub fn support_rate(&self) -> f64 {
        if self.total_processes == 0 {
            return 100.0;
        }
        (self.fully_supported as f64 / self.total_processes as f64) * 100.0
    }

    pub fn has_compatibility_issues(&self) -> bool {
        self.unsupported > 0 || self.unknown > 0
    }
}
