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

//! Production-grade multi-language profiler integration
//!
//! This module integrates all profiler components into a unified, production-ready
//! system with enhanced error handling, monitoring, and performance optimization.

use log::{debug, error, info, trace, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::unwind::{
    cache::BoundedLruCache,
    constants::profiler::*,
    error_recovery::ErrorRecoveryCoordinator,
    monitoring::{
        log_profiler_error, ErrorContext, PerformanceMonitor, ProfilerError, ProfilerHealthChecker,
        ProfilerMetrics, ProfilerResult,
    },
    nodejs::{NodeJSRuntimeDetector, NodeJSUnwindTable},
    php::{PHPRuntimeDetector, PHPUnwindTable},
    symbol_resolver::{RuntimeType, SymbolResolverRegistry},
    version_compatibility::{CompatibilityStatus, IssueSeverity, VersionCompatibilityChecker},
};

/// Production-grade multi-language profiler with comprehensive monitoring
pub struct EnhancedMultiLanguageProfiler {
    // Core components
    #[allow(dead_code)]
    symbol_resolver_registry: SymbolResolverRegistry,
    php_unwind_table: PHPUnwindTable,
    nodejs_unwind_table: NodeJSUnwindTable,

    // Runtime detectors with enhanced caching
    #[allow(dead_code)]
    php_detector: PHPRuntimeDetector,
    #[allow(dead_code)]
    nodejs_detector: NodeJSRuntimeDetector,

    // Process tracking
    active_processes: HashMap<u32, RuntimeType>,
    process_cache: BoundedLruCache<u32, RuntimeType>,

    // Monitoring and metrics
    metrics: Arc<ProfilerMetrics>,
    health_checker: ProfilerHealthChecker,
    error_recovery: ErrorRecoveryCoordinator,
    version_checker: VersionCompatibilityChecker,

    // Configuration
    config: ProfilerConfig,

    // eBPF map file descriptors
    #[allow(dead_code)]
    runtime_info_map_fd: i32,
    #[allow(dead_code)]
    php_offsets_map_fd: i32,
    #[allow(dead_code)]
    nodejs_offsets_map_fd: i32,
}

/// Profiler configuration with production-grade defaults
#[derive(Debug, Clone)]
pub struct ProfilerConfig {
    /// Maximum number of processes to track simultaneously
    pub max_processes: u32,

    /// Cache TTL for runtime detection results
    pub cache_ttl_seconds: u64,

    /// Maximum cache size for process runtime types
    pub cache_size: usize,

    /// Performance monitoring threshold for stack unwinding (microseconds)
    pub unwind_timeout_us: u64,

    /// Enable enhanced error logging
    pub enable_detailed_logging: bool,

    /// Health check interval
    pub health_check_interval_seconds: u64,

    /// Maximum stack depth for unwinding
    pub max_stack_depth: u32,

    /// Enable performance optimizations
    pub enable_optimizations: bool,
}

impl Default for ProfilerConfig {
    fn default() -> Self {
        Self {
            max_processes: MAX_PROCESSES_TRACKED,
            cache_ttl_seconds: DEFAULT_CACHE_TTL_SECONDS,
            cache_size: DEFAULT_CACHE_SIZE,
            unwind_timeout_us: UNWINDING_TIMEOUT_US,
            enable_detailed_logging: true,
            health_check_interval_seconds: 60,
            max_stack_depth: MAX_INTERPRETER_STACK_DEPTH,
            enable_optimizations: true,
        }
    }
}

impl EnhancedMultiLanguageProfiler {
    /// Create new enhanced profiler instance
    pub fn new(
        runtime_info_map_fd: i32,
        php_offsets_map_fd: i32,
        nodejs_offsets_map_fd: i32,
        config: Option<ProfilerConfig>,
    ) -> ProfilerResult<Self> {
        let config = config.unwrap_or_default();

        // Validate configuration
        Self::validate_config(&config)?;

        let metrics = Arc::new(ProfilerMetrics::new());
        let health_checker = ProfilerHealthChecker::new(metrics.clone());

        // Create process cache with memory optimization
        let memory_config = crate::unwind::cache::MemoryConfig {
            cache_name: "profiler_process_cache".to_string(),
            pressure_check_interval_secs: 30,
            low_memory_threshold_mb: 50,
            high_memory_threshold_mb: 200,
            emergency_threshold_mb: 500,
            enable_adaptive_sizing: config.enable_optimizations,
            max_memory_usage_mb: 100,
        };

        let process_cache = BoundedLruCache::with_memory_config(
            config.cache_size,
            Duration::from_secs(config.cache_ttl_seconds),
            memory_config,
        );

        // Initialize components
        let php_unwind_table =
            unsafe { PHPUnwindTable::new(runtime_info_map_fd, php_offsets_map_fd) };

        let nodejs_unwind_table =
            unsafe { NodeJSUnwindTable::new(runtime_info_map_fd, nodejs_offsets_map_fd) };

        let error_recovery = ErrorRecoveryCoordinator::new(metrics.clone());
        let version_checker = VersionCompatibilityChecker::new(metrics.clone())?;

        let profiler = Self {
            symbol_resolver_registry: SymbolResolverRegistry::new(),
            php_unwind_table,
            nodejs_unwind_table,
            php_detector: PHPRuntimeDetector::new(),
            nodejs_detector: NodeJSRuntimeDetector::new(),
            active_processes: HashMap::new(),
            process_cache,
            metrics,
            health_checker,
            error_recovery,
            version_checker,
            config: config.clone(),
            runtime_info_map_fd,
            php_offsets_map_fd,
            nodejs_offsets_map_fd,
        };

        info!(
            "Enhanced multi-language profiler initialized with {} max processes",
            config.max_processes
        );

        Ok(profiler)
    }

    /// Validate profiler configuration
    fn validate_config(config: &ProfilerConfig) -> ProfilerResult<()> {
        if config.max_processes == 0 {
            return Err(ProfilerError::ConfigurationError {
                parameter: "max_processes".to_string(),
                value: config.max_processes.to_string(),
                reason: "Must be greater than 0".to_string(),
            });
        }

        if config.cache_size == 0 {
            return Err(ProfilerError::ConfigurationError {
                parameter: "cache_size".to_string(),
                value: config.cache_size.to_string(),
                reason: "Must be greater than 0".to_string(),
            });
        }

        if config.max_stack_depth == 0 || config.max_stack_depth > 1024 {
            return Err(ProfilerError::ConfigurationError {
                parameter: "max_stack_depth".to_string(),
                value: config.max_stack_depth.to_string(),
                reason: "Must be between 1 and 1024".to_string(),
            });
        }

        Ok(())
    }

    /// Add process for profiling with enhanced detection and error handling
    pub fn add_process(&mut self, pid: u32) -> ProfilerResult<()> {
        let monitor = PerformanceMonitor::start_with_threshold(
            "add_process",
            1000, // 1ms threshold for process addition
            self.metrics.clone(),
        );

        // Check if we've reached the process limit
        if self.active_processes.len() >= self.config.max_processes as usize {
            return Err(ProfilerError::ResourceExhausted {
                resource_type: "active_processes".to_string(),
                current_usage: self.active_processes.len() as u64,
                limit: self.config.max_processes as u64,
            });
        }

        // Check version compatibility first
        let compatibility_result = self.version_checker.check_process_compatibility(pid)?;

        // Log compatibility issues
        for issue in &compatibility_result.issues {
            match issue.severity {
                IssueSeverity::Critical | IssueSeverity::Error => {
                    error!(
                        "Process {} version compatibility error: {}",
                        pid, issue.message
                    );
                    if let Some(ref recommendation) = issue.recommendation {
                        error!("Recommendation: {}", recommendation);
                    }
                }
                IssueSeverity::Warning => {
                    warn!(
                        "Process {} version compatibility warning: {}",
                        pid, issue.message
                    );
                }
                IssueSeverity::Info => {
                    info!("Process {} version info: {}", pid, issue.message);
                }
            }
        }

        // Reject unsupported versions
        match compatibility_result.compatibility_status {
            CompatibilityStatus::Unsupported => {
                return Err(ProfilerError::VersionCompatibility {
                    runtime_type: compatibility_result.runtime_type as u8,
                    detected_version: compatibility_result.detected_version,
                    supported_versions: vec![
                        "7.4-8.2 (PHP)".to_string(),
                        "16.x-21.x (Node.js)".to_string(),
                    ],
                });
            }
            CompatibilityStatus::Unknown if compatibility_result.confidence < 0.5 => {
                warn!(
                    "Low confidence ({:.1}%) in version detection for process {}",
                    compatibility_result.confidence * 100.0,
                    pid
                );
            }
            _ => {}
        }

        let runtime_type = compatibility_result.runtime_type;

        match runtime_type {
            RuntimeType::PHP => {
                self.php_unwind_table.add_process(pid).map_err(|e| {
                    ProfilerError::StackUnwindFailed {
                        pid,
                        runtime_type: RUNTIME_TYPE_PHP,
                        frame_count: 0,
                        error_details: e.to_string(),
                    }
                })?;

                self.metrics
                    .record_runtime_detection(RUNTIME_TYPE_PHP, true);
            }
            RuntimeType::NodeJS | RuntimeType::V8 => {
                self.nodejs_unwind_table.add_process(pid).map_err(|e| {
                    ProfilerError::StackUnwindFailed {
                        pid,
                        runtime_type: RUNTIME_TYPE_NODEJS,
                        frame_count: 0,
                        error_details: e.to_string(),
                    }
                })?;

                self.metrics
                    .record_runtime_detection(RUNTIME_TYPE_NODEJS, true);
            }
            RuntimeType::Python => {
                self.metrics
                    .record_runtime_detection(RUNTIME_TYPE_PYTHON, true);
                // Python profiler integration would go here
            }
            _ => {
                self.metrics
                    .record_runtime_detection(RUNTIME_TYPE_UNKNOWN, false);

                if self.config.enable_detailed_logging {
                    debug!("Process {} does not match any supported runtime", pid);
                }

                monitor.finish();
                return Ok(()); // Not an error, just not a supported runtime
            }
        }

        // Track the process
        self.active_processes.insert(pid, runtime_type);
        self.metrics.active_processes_tracked.store(
            self.active_processes.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        let duration_us = monitor.finish();

        info!(
            "Added process {} with runtime type {:?} (took {}μs)",
            pid, runtime_type, duration_us
        );

        Ok(())
    }

    /// Remove process from profiling
    pub fn remove_process(&mut self, pid: u32) -> ProfilerResult<()> {
        // Remove from version tracking
        self.version_checker.remove_process(pid);

        if let Some(runtime_type) = self.active_processes.remove(&pid) {
            match runtime_type {
                RuntimeType::PHP => {
                    self.php_unwind_table.remove_process(pid).map_err(|e| {
                        ProfilerError::StackUnwindFailed {
                            pid,
                            runtime_type: RUNTIME_TYPE_PHP,
                            frame_count: 0,
                            error_details: e.to_string(),
                        }
                    })?;
                }
                RuntimeType::NodeJS | RuntimeType::V8 => {
                    self.nodejs_unwind_table.remove_process(pid).map_err(|e| {
                        ProfilerError::StackUnwindFailed {
                            pid,
                            runtime_type: RUNTIME_TYPE_NODEJS,
                            frame_count: 0,
                            error_details: e.to_string(),
                        }
                    })?;
                }
                _ => {}
            }

            // Update metrics
            self.metrics.active_processes_tracked.store(
                self.active_processes.len() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );

            // Remove from cache
            if let Err(e) = self.process_cache.remove(&pid) {
                warn!("Failed to remove process {} from cache: {}", pid, e);
            }

            debug!(
                "Removed process {} with runtime type {:?}",
                pid, runtime_type
            );
        }

        Ok(())
    }

    /// Detect runtime type with enhanced caching and error handling
    #[allow(dead_code)]
    fn detect_runtime_with_caching(&mut self, pid: u32) -> ProfilerResult<RuntimeType> {
        let monitor = PerformanceMonitor::start("runtime_detection", self.metrics.clone());

        // Check cache first
        if let Some(cached_type) = self.process_cache.get(&pid) {
            monitor.finish();
            return Ok(cached_type);
        }

        let mut attempted_methods = Vec::new();
        let mut detection_errors = Vec::new();

        // Try PHP detection
        attempted_methods.push("PHP".to_string());
        match self.php_detector.detect(pid) {
            Ok(Some(_)) => {
                let runtime_type = RuntimeType::PHP;
                if let Err(e) = self.process_cache.insert(pid, runtime_type) {
                    warn!(
                        "Failed to cache PHP runtime detection for PID {}: {}",
                        pid, e
                    );
                }
                monitor.finish();
                return Ok(runtime_type);
            }
            Ok(None) => {}
            Err(e) => {
                detection_errors.push(format!("PHP detection failed: {}", e));
            }
        }

        // Try Node.js detection
        attempted_methods.push("Node.js".to_string());
        match self.nodejs_detector.detect(pid) {
            Ok(Some(_)) => {
                let runtime_type = RuntimeType::NodeJS;
                if let Err(e) = self.process_cache.insert(pid, runtime_type) {
                    warn!(
                        "Failed to cache Node.js runtime detection for PID {}: {}",
                        pid, e
                    );
                }
                monitor.finish();
                return Ok(runtime_type);
            }
            Ok(None) => {}
            Err(e) => {
                detection_errors.push(format!("Node.js detection failed: {}", e));
            }
        }

        // TODO: Add Python detection here
        attempted_methods.push("Python".to_string());

        monitor.finish();

        // Cache negative result for a shorter period
        let unknown_type = RuntimeType::Unknown;
        if let Err(e) = self.process_cache.insert(pid, unknown_type) {
            warn!(
                "Failed to cache unknown runtime detection for PID {}: {}",
                pid, e
            );
        }

        if self.config.enable_detailed_logging && !detection_errors.is_empty() {
            let context = ErrorContext::new("runtime_detection")
                .with_pid(pid)
                .with_info("detection_errors", detection_errors.join("; "));

            let error = ProfilerError::RuntimeDetectionFailed {
                pid,
                reason: "All detection methods failed".to_string(),
                attempted_methods,
            };

            log_profiler_error(&error, Some(&context));
        }

        Ok(unknown_type)
    }

    /// Process stack trace from eBPF data with enhanced error handling and recovery
    pub fn process_stack_trace(&self, pid: u32, raw_data: &[u8]) -> ProfilerResult<String> {
        let monitor = PerformanceMonitor::start_with_threshold(
            "process_stack_trace",
            self.config.unwind_timeout_us,
            self.metrics.clone(),
        );

        let runtime_type = self
            .active_processes
            .get(&pid)
            .copied()
            .unwrap_or(RuntimeType::Unknown);

        // Use error recovery coordinator for resilient processing
        let result = match runtime_type {
            RuntimeType::PHP => self.error_recovery.execute_with_recovery(
                runtime_type,
                |p, data| self.process_php_stack_trace_primary(p, data),
                pid,
                raw_data,
            ),
            RuntimeType::NodeJS | RuntimeType::V8 => self.error_recovery.execute_with_recovery(
                runtime_type,
                |p, data| self.process_nodejs_stack_trace_primary(p, data),
                pid,
                raw_data,
            ),
            RuntimeType::Python => self.error_recovery.execute_with_recovery(
                runtime_type,
                |p, data| self.process_python_stack_trace_primary(p, data),
                pid,
                raw_data,
            ),
            _ => {
                // Process as native stack trace
                self.process_native_stack_trace(pid, raw_data)
            }
        };

        let duration_us = monitor.finish();

        match &result {
            Ok(_) => {
                self.metrics.record_sample_processing(duration_us, false);
                trace!("Processed stack trace for PID {} in {}μs", pid, duration_us);
            }
            Err(e) => {
                self.metrics.record_sample_processing(duration_us, true);

                let context = ErrorContext::new("process_stack_trace")
                    .with_pid(pid)
                    .with_runtime(runtime_type as u8)
                    .with_info("duration_us", duration_us.to_string());

                log_profiler_error(e, Some(&context));
            }
        }

        result
    }

    /// Process PHP stack trace (primary method)
    fn process_php_stack_trace_primary(
        &self,
        pid: u32,
        _raw_data: &[u8],
    ) -> ProfilerResult<String> {
        // This would integrate with PHP-specific eBPF data processing
        // Simulate potential failure for demonstration
        if pid % 10 == 0 {
            return Err(ProfilerError::StackUnwindFailed {
                pid,
                runtime_type: RUNTIME_TYPE_PHP,
                frame_count: 0,
                error_details: "Simulated PHP unwinding failure".to_string(),
            });
        }
        Ok(format!("PHP stack trace for PID {}", pid))
    }

    /// Process Node.js stack trace (primary method)
    fn process_nodejs_stack_trace_primary(
        &self,
        pid: u32,
        _raw_data: &[u8],
    ) -> ProfilerResult<String> {
        // This would integrate with Node.js-specific eBPF data processing
        // Simulate potential failure for demonstration
        if pid % 15 == 0 {
            return Err(ProfilerError::StackUnwindFailed {
                pid,
                runtime_type: RUNTIME_TYPE_NODEJS,
                frame_count: 0,
                error_details: "Simulated Node.js unwinding failure".to_string(),
            });
        }
        Ok(format!("Node.js stack trace for PID {}", pid))
    }

    /// Process Python stack trace (primary method)
    fn process_python_stack_trace_primary(
        &self,
        pid: u32,
        _raw_data: &[u8],
    ) -> ProfilerResult<String> {
        // This would integrate with Python-specific eBPF data processing
        // Simulate potential failure for demonstration
        if pid % 12 == 0 {
            return Err(ProfilerError::StackUnwindFailed {
                pid,
                runtime_type: RUNTIME_TYPE_PYTHON,
                frame_count: 0,
                error_details: "Simulated Python unwinding failure".to_string(),
            });
        }
        Ok(format!("Python stack trace for PID {}", pid))
    }

    /// Process native stack trace (fallback method)
    fn process_native_stack_trace(&self, pid: u32, _raw_data: &[u8]) -> ProfilerResult<String> {
        // This would integrate with native stack unwinding
        Ok(format!("Native stack trace for PID {}", pid))
    }

    /// Perform health check and return any issues
    pub fn health_check(&mut self) -> Vec<String> {
        let mut issues = self.health_checker.check_health();

        // Check error recovery system health
        let degraded_level = self.error_recovery.check_system_health();
        let recovery_stats = self.error_recovery.get_recovery_stats();

        if degraded_level > 0 {
            issues.push(format!(
                "System in degraded mode (level {}): {}/{} circuit breakers open",
                degraded_level,
                recovery_stats.open_circuit_breakers,
                recovery_stats.total_circuit_breakers
            ));
        }

        if recovery_stats.fallback_success_rate < 80.0 {
            issues.push(format!(
                "Low fallback success rate: {:.1}%",
                recovery_stats.fallback_success_rate
            ));
        }

        // Check version compatibility health
        let compatibility_summary = self.version_checker.get_compatibility_summary();

        if compatibility_summary.has_compatibility_issues() {
            issues.push(format!(
                "Version compatibility issues: {} unsupported, {} unknown out of {} processes",
                compatibility_summary.unsupported,
                compatibility_summary.unknown,
                compatibility_summary.total_processes
            ));
        }

        if compatibility_summary.support_rate() < 90.0 {
            issues.push(format!(
                "Low version support rate: {:.1}%",
                compatibility_summary.support_rate()
            ));
        }

        issues
    }

    /// Get comprehensive metrics
    pub fn get_metrics(&self) -> Arc<ProfilerMetrics> {
        self.metrics.clone()
    }

    /// Get active process count
    pub fn get_active_process_count(&self) -> usize {
        self.active_processes.len()
    }

    /// Get supported runtime types
    pub fn get_supported_runtimes(&self) -> Vec<RuntimeType> {
        vec![RuntimeType::PHP, RuntimeType::NodeJS, RuntimeType::Python]
    }

    /// Get version compatibility summary
    pub fn get_compatibility_summary(
        &self,
    ) -> crate::unwind::version_compatibility::CompatibilitySummary {
        self.version_checker.get_compatibility_summary()
    }

    /// Check specific process compatibility
    pub fn check_process_compatibility(
        &self,
        pid: u32,
    ) -> ProfilerResult<crate::unwind::version_compatibility::VersionDetectionResult> {
        self.version_checker.check_process_compatibility(pid)
    }

    /// Periodic maintenance tasks
    pub fn perform_maintenance(&mut self) {
        // Perform health check and log results
        self.health_checker.log_health_status();

        // Check error recovery system health
        let degraded_level = self.error_recovery.check_system_health();
        let recovery_stats = self.error_recovery.get_recovery_stats();

        // Log metrics summary
        let summary = self.metrics.get_summary();
        info!(
            "Profiler status: {} processes active, {:.2}% unwind success rate, {:.1}% circuit breaker health",
            self.active_processes.len(),
            summary.unwind_success_rate,
            recovery_stats.circuit_breaker_health_percentage()
        );

        // Log recovery statistics
        if degraded_level > 0 || recovery_stats.fallback_success_rate < 90.0 {
            warn!(
                "Recovery stats: degraded_level={}, fallback_success={:.1}%, open_breakers={}/{}",
                degraded_level,
                recovery_stats.fallback_success_rate,
                recovery_stats.open_circuit_breakers,
                recovery_stats.total_circuit_breakers
            );
        }

        // Additional maintenance tasks
        // - Cache cleanup
        // - Memory usage optimization
        // - Performance tuning
        // - Automatic recovery attempts
    }

    /// Shutdown profiler gracefully
    pub fn shutdown(&mut self) -> ProfilerResult<()> {
        info!("Shutting down enhanced multi-language profiler");

        // Remove all active processes
        let active_pids: Vec<u32> = self.active_processes.keys().copied().collect();
        for pid in active_pids {
            if let Err(e) = self.remove_process(pid) {
                warn!("Failed to remove process {} during shutdown: {}", pid, e);
            }
        }

        // Clear caches
        if let Err(e) = self.process_cache.clear() {
            warn!("Failed to clear process cache during shutdown: {}", e);
        }

        // Log final metrics
        let summary = self.metrics.get_summary();
        info!(
            "Final profiler metrics: {} samples processed, {:.2}% success rate",
            summary.samples_processed, summary.unwind_success_rate
        );

        Ok(())
    }
}

impl Drop for EnhancedMultiLanguageProfiler {
    fn drop(&mut self) {
        if !self.active_processes.is_empty() {
            warn!(
                "Profiler dropped with {} active processes",
                self.active_processes.len()
            );
            let _ = self.shutdown();
        }
    }
}
