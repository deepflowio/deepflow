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

//! Enhanced error handling and monitoring for multi-language profiler
//!
//! This module provides comprehensive error handling, metrics collection,
//! and monitoring capabilities for the production-grade profiler.

use crate::unwind::constants::profiler::*;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Multi-language profiler error types with detailed context
#[derive(Debug, Clone)]
pub enum ProfilerError {
    /// Runtime detection errors
    RuntimeDetectionFailed {
        pid: u32,
        reason: String,
        attempted_methods: Vec<String>,
    },

    /// Memory access errors
    InvalidMemoryAccess {
        address: u64,
        size: usize,
        context: String,
    },

    /// Symbol resolution errors
    SymbolResolutionFailed {
        address: u64,
        runtime_type: u8,
        reason: String,
    },

    /// Stack unwinding errors
    StackUnwindFailed {
        pid: u32,
        runtime_type: u8,
        frame_count: u32,
        error_details: String,
    },

    /// Cache operation errors
    CacheError {
        operation: String,
        key: String,
        reason: String,
    },

    /// eBPF map operation errors
    BpfMapError {
        map_name: String,
        operation: String,
        return_code: i32,
        errno: i32,
    },

    /// Configuration errors
    ConfigurationError {
        parameter: String,
        value: String,
        reason: String,
    },

    /// Resource exhaustion errors
    ResourceExhausted {
        resource_type: String,
        current_usage: u64,
        limit: u64,
    },

    /// Version compatibility errors
    VersionCompatibility {
        runtime_type: u8,
        detected_version: String,
        supported_versions: Vec<String>,
    },

    /// Performance threshold exceeded
    PerformanceThresholdExceeded {
        operation: String,
        duration_us: u64,
        threshold_us: u64,
    },

    /// Fallback mechanism errors
    FallbackFailed {
        primary_error: String,
        fallback_error: String,
        pid: u32,
        runtime_type: u8,
    },

    /// Circuit breaker activated
    CircuitBreakerOpen {
        runtime_type: u8,
        failure_count: u64,
        threshold: u64,
    },
}

impl fmt::Display for ProfilerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfilerError::RuntimeDetectionFailed {
                pid,
                reason,
                attempted_methods,
            } => {
                write!(
                    f,
                    "Runtime detection failed for PID {}: {}. Attempted methods: {}",
                    pid,
                    reason,
                    attempted_methods.join(", ")
                )
            }
            ProfilerError::InvalidMemoryAccess {
                address,
                size,
                context,
            } => {
                write!(
                    f,
                    "Invalid memory access at 0x{:x} (size: {}) in context: {}",
                    address, size, context
                )
            }
            ProfilerError::SymbolResolutionFailed {
                address,
                runtime_type,
                reason,
            } => {
                write!(
                    f,
                    "Symbol resolution failed for address 0x{:x} (runtime: {}) - {}",
                    address, runtime_type, reason
                )
            }
            ProfilerError::StackUnwindFailed {
                pid,
                runtime_type,
                frame_count,
                error_details,
            } => {
                write!(
                    f,
                    "Stack unwinding failed for PID {} (runtime: {}, frames: {}) - {}",
                    pid, runtime_type, frame_count, error_details
                )
            }
            ProfilerError::CacheError {
                operation,
                key,
                reason,
            } => {
                write!(
                    f,
                    "Cache {} operation failed for key '{}': {}",
                    operation, key, reason
                )
            }
            ProfilerError::BpfMapError {
                map_name,
                operation,
                return_code,
                errno,
            } => {
                write!(
                    f,
                    "BPF map '{}' {} operation failed: return_code={}, errno={}",
                    map_name, operation, return_code, errno
                )
            }
            ProfilerError::ConfigurationError {
                parameter,
                value,
                reason,
            } => {
                write!(
                    f,
                    "Configuration error for parameter '{}' with value '{}': {}",
                    parameter, value, reason
                )
            }
            ProfilerError::ResourceExhausted {
                resource_type,
                current_usage,
                limit,
            } => {
                write!(
                    f,
                    "Resource '{}' exhausted: {} / {} (usage/limit)",
                    resource_type, current_usage, limit
                )
            }
            ProfilerError::VersionCompatibility {
                runtime_type,
                detected_version,
                supported_versions,
            } => {
                write!(
                    f,
                    "Version compatibility error for runtime {}: detected '{}', supported: [{}]",
                    runtime_type,
                    detected_version,
                    supported_versions.join(", ")
                )
            }
            ProfilerError::PerformanceThresholdExceeded {
                operation,
                duration_us,
                threshold_us,
            } => {
                write!(
                    f,
                    "Performance threshold exceeded for '{}': {}μs > {}μs",
                    operation, duration_us, threshold_us
                )
            }
            ProfilerError::FallbackFailed {
                primary_error,
                fallback_error,
                pid,
                runtime_type,
            } => {
                write!(
                    f,
                    "Both primary and fallback profiling failed for PID {} (runtime: {}). Primary: {}, Fallback: {}",
                    pid, runtime_type, primary_error, fallback_error
                )
            }
            ProfilerError::CircuitBreakerOpen {
                runtime_type,
                failure_count,
                threshold,
            } => {
                write!(
                    f,
                    "Circuit breaker open for runtime {}: {} failures >= {} threshold",
                    runtime_type, failure_count, threshold
                )
            }
        }
    }
}

impl std::error::Error for ProfilerError {}

/// Result type for profiler operations
pub type ProfilerResult<T> = Result<T, ProfilerError>;

/// Comprehensive metrics collection for profiler performance monitoring
#[derive(Debug, Default)]
pub struct ProfilerMetrics {
    // Stack unwinding metrics
    pub stack_unwind_attempts: AtomicU64,
    pub stack_unwind_successes: AtomicU64,
    pub stack_unwind_failures: AtomicU64,
    pub total_unwind_time_us: AtomicU64,
    pub max_unwind_time_us: AtomicU64,

    // Symbol resolution metrics
    pub symbol_resolution_attempts: AtomicU64,
    pub symbol_resolution_successes: AtomicU64,
    pub symbol_resolution_cache_hits: AtomicU64,
    pub symbol_resolution_cache_misses: AtomicU64,

    // Runtime detection metrics
    pub runtime_detection_attempts: AtomicU64,
    pub runtime_detection_successes: AtomicU64,
    pub php_runtime_detections: AtomicU64,
    pub nodejs_runtime_detections: AtomicU64,
    pub python_runtime_detections: AtomicU64,

    // Memory access metrics
    pub memory_read_attempts: AtomicU64,
    pub memory_read_failures: AtomicU64,
    pub invalid_pointer_accesses: AtomicU64,

    // Cache performance metrics
    pub cache_operations: AtomicU64,
    pub cache_hit_ratio: AtomicU64, // Stored as percentage * 100
    pub cache_evictions: AtomicU64,

    // eBPF metrics
    pub ebpf_program_executions: AtomicU64,
    pub ebpf_tail_call_failures: AtomicU64,
    pub ebpf_map_update_failures: AtomicU64,

    // Performance metrics
    pub samples_processed: AtomicU64,
    pub samples_dropped: AtomicU64,
    pub avg_processing_time_us: AtomicU64,

    // Error metrics by category
    pub configuration_errors: AtomicU64,
    pub resource_exhaustion_errors: AtomicU64,
    pub version_compatibility_errors: AtomicU64,
    pub bpf_errors: AtomicU64,

    // Fallback and recovery metrics
    pub fallback_attempts: AtomicU64,
    pub fallback_successes: AtomicU64,
    pub circuit_breaker_activations: AtomicU64,
    pub automatic_recoveries: AtomicU64,

    // System resource metrics
    pub active_processes_tracked: AtomicU64,
    pub memory_usage_bytes: AtomicU64,
    pub cpu_usage_percent: AtomicU64, // Stored as percentage * 100
}

impl ProfilerMetrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Record stack unwinding attempt
    pub fn record_unwind_attempt(&self, duration_us: u64, success: bool) {
        self.stack_unwind_attempts.fetch_add(1, Ordering::Relaxed);
        self.total_unwind_time_us
            .fetch_add(duration_us, Ordering::Relaxed);

        // Update max unwind time atomically
        let mut current_max = self.max_unwind_time_us.load(Ordering::Relaxed);
        while duration_us > current_max {
            match self.max_unwind_time_us.compare_exchange_weak(
                current_max,
                duration_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_max = actual,
            }
        }

        if success {
            self.stack_unwind_successes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stack_unwind_failures.fetch_add(1, Ordering::Relaxed);
        }

        // Check performance threshold
        if duration_us > UNWINDING_TIMEOUT_US {
            warn!(
                "Stack unwinding exceeded performance threshold: {}μs > {}μs",
                duration_us, UNWINDING_TIMEOUT_US
            );
        }
    }

    /// Record symbol resolution attempt
    pub fn record_symbol_resolution(&self, cache_hit: bool, success: bool) {
        self.symbol_resolution_attempts
            .fetch_add(1, Ordering::Relaxed);

        if cache_hit {
            self.symbol_resolution_cache_hits
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.symbol_resolution_cache_misses
                .fetch_add(1, Ordering::Relaxed);
        }

        if success {
            self.symbol_resolution_successes
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record runtime detection
    pub fn record_runtime_detection(&self, runtime_type: u8, success: bool) {
        self.runtime_detection_attempts
            .fetch_add(1, Ordering::Relaxed);

        if success {
            self.runtime_detection_successes
                .fetch_add(1, Ordering::Relaxed);

            match runtime_type {
                RUNTIME_TYPE_PHP => self.php_runtime_detections.fetch_add(1, Ordering::Relaxed),
                RUNTIME_TYPE_NODEJS | RUNTIME_TYPE_V8 => self
                    .nodejs_runtime_detections
                    .fetch_add(1, Ordering::Relaxed),
                RUNTIME_TYPE_PYTHON => self
                    .python_runtime_detections
                    .fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
        }
    }

    /// Record memory access attempt
    pub fn record_memory_access(&self, success: bool) {
        self.memory_read_attempts.fetch_add(1, Ordering::Relaxed);

        if !success {
            self.memory_read_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record invalid pointer access
    pub fn record_invalid_pointer(&self) {
        self.invalid_pointer_accesses
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record eBPF operation
    pub fn record_ebpf_execution(&self) {
        self.ebpf_program_executions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record eBPF tail call failure
    pub fn record_tail_call_failure(&self) {
        self.ebpf_tail_call_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record sample processing
    pub fn record_sample_processing(&self, processing_time_us: u64, dropped: bool) {
        if dropped {
            self.samples_dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            self.samples_processed.fetch_add(1, Ordering::Relaxed);
        }

        // Update average processing time using exponential moving average
        let current_avg = self.avg_processing_time_us.load(Ordering::Relaxed);
        let new_avg = if current_avg == 0 {
            processing_time_us
        } else {
            // EMA with alpha = 0.1 (90% previous, 10% current)
            (current_avg * 9 + processing_time_us) / 10
        };
        self.avg_processing_time_us
            .store(new_avg, Ordering::Relaxed);
    }

    /// Record fallback attempt
    pub fn record_fallback_attempt(&self, success: bool) {
        self.fallback_attempts.fetch_add(1, Ordering::Relaxed);
        if success {
            self.fallback_successes.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record circuit breaker activation
    pub fn record_circuit_breaker_activation(&self) {
        self.circuit_breaker_activations
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record automatic recovery
    pub fn record_automatic_recovery(&self) {
        self.automatic_recoveries.fetch_add(1, Ordering::Relaxed);
    }

    /// Get fallback success rate
    pub fn get_fallback_success_rate(&self) -> f64 {
        let attempts = self.fallback_attempts.load(Ordering::Relaxed);
        if attempts == 0 {
            return 0.0;
        }
        let successes = self.fallback_successes.load(Ordering::Relaxed);
        (successes as f64) / (attempts as f64) * 100.0
    }

    /// Get success rate for stack unwinding
    pub fn get_unwind_success_rate(&self) -> f64 {
        let attempts = self.stack_unwind_attempts.load(Ordering::Relaxed);
        if attempts == 0 {
            return 0.0;
        }

        let successes = self.stack_unwind_successes.load(Ordering::Relaxed);
        (successes as f64) / (attempts as f64) * 100.0
    }

    /// Get average unwinding time
    pub fn get_avg_unwind_time_us(&self) -> f64 {
        let attempts = self.stack_unwind_attempts.load(Ordering::Relaxed);
        if attempts == 0 {
            return 0.0;
        }

        let total_time = self.total_unwind_time_us.load(Ordering::Relaxed);
        (total_time as f64) / (attempts as f64)
    }

    /// Get symbol resolution cache hit rate
    pub fn get_symbol_cache_hit_rate(&self) -> f64 {
        let hits = self.symbol_resolution_cache_hits.load(Ordering::Relaxed);
        let misses = self.symbol_resolution_cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;

        if total == 0 {
            return 0.0;
        }
        (hits as f64) / (total as f64) * 100.0
    }

    /// Get runtime detection success rate
    pub fn get_runtime_detection_rate(&self) -> f64 {
        let attempts = self.runtime_detection_attempts.load(Ordering::Relaxed);
        if attempts == 0 {
            return 0.0;
        }

        let successes = self.runtime_detection_successes.load(Ordering::Relaxed);
        (successes as f64) / (attempts as f64) * 100.0
    }

    /// Get comprehensive metrics summary
    pub fn get_summary(&self) -> ProfilerMetricsSummary {
        ProfilerMetricsSummary {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),

            // Unwinding metrics
            unwind_success_rate: self.get_unwind_success_rate(),
            avg_unwind_time_us: self.get_avg_unwind_time_us(),
            max_unwind_time_us: self.max_unwind_time_us.load(Ordering::Relaxed),
            total_unwind_attempts: self.stack_unwind_attempts.load(Ordering::Relaxed),

            // Symbol resolution metrics
            symbol_cache_hit_rate: self.get_symbol_cache_hit_rate(),
            symbol_resolution_attempts: self.symbol_resolution_attempts.load(Ordering::Relaxed),

            // Runtime detection metrics
            runtime_detection_rate: self.get_runtime_detection_rate(),
            php_detections: self.php_runtime_detections.load(Ordering::Relaxed),
            nodejs_detections: self.nodejs_runtime_detections.load(Ordering::Relaxed),
            python_detections: self.python_runtime_detections.load(Ordering::Relaxed),

            // Error metrics
            memory_read_failures: self.memory_read_failures.load(Ordering::Relaxed),
            invalid_pointer_accesses: self.invalid_pointer_accesses.load(Ordering::Relaxed),
            tail_call_failures: self.ebpf_tail_call_failures.load(Ordering::Relaxed),

            // Performance metrics
            samples_processed: self.samples_processed.load(Ordering::Relaxed),
            samples_dropped: self.samples_dropped.load(Ordering::Relaxed),
            avg_processing_time_us: self.avg_processing_time_us.load(Ordering::Relaxed),

            // System metrics
            active_processes: self.active_processes_tracked.load(Ordering::Relaxed),
            memory_usage_bytes: self.memory_usage_bytes.load(Ordering::Relaxed),
        }
    }

    /// Reset all metrics (useful for testing or periodic resets)
    pub fn reset(&self) {
        // Reset all atomic counters
        self.stack_unwind_attempts.store(0, Ordering::Relaxed);
        self.stack_unwind_successes.store(0, Ordering::Relaxed);
        self.stack_unwind_failures.store(0, Ordering::Relaxed);
        self.total_unwind_time_us.store(0, Ordering::Relaxed);
        self.max_unwind_time_us.store(0, Ordering::Relaxed);

        self.symbol_resolution_attempts.store(0, Ordering::Relaxed);
        self.symbol_resolution_successes.store(0, Ordering::Relaxed);
        self.symbol_resolution_cache_hits
            .store(0, Ordering::Relaxed);
        self.symbol_resolution_cache_misses
            .store(0, Ordering::Relaxed);

        self.runtime_detection_attempts.store(0, Ordering::Relaxed);
        self.runtime_detection_successes.store(0, Ordering::Relaxed);
        self.php_runtime_detections.store(0, Ordering::Relaxed);
        self.nodejs_runtime_detections.store(0, Ordering::Relaxed);
        self.python_runtime_detections.store(0, Ordering::Relaxed);

        self.memory_read_attempts.store(0, Ordering::Relaxed);
        self.memory_read_failures.store(0, Ordering::Relaxed);
        self.invalid_pointer_accesses.store(0, Ordering::Relaxed);

        self.ebpf_program_executions.store(0, Ordering::Relaxed);
        self.ebpf_tail_call_failures.store(0, Ordering::Relaxed);
        self.ebpf_map_update_failures.store(0, Ordering::Relaxed);

        self.samples_processed.store(0, Ordering::Relaxed);
        self.samples_dropped.store(0, Ordering::Relaxed);
        self.avg_processing_time_us.store(0, Ordering::Relaxed);

        self.fallback_attempts.store(0, Ordering::Relaxed);
        self.fallback_successes.store(0, Ordering::Relaxed);
        self.circuit_breaker_activations.store(0, Ordering::Relaxed);
        self.automatic_recoveries.store(0, Ordering::Relaxed);
    }
}

/// Metrics summary structure for reporting
#[derive(Debug, Clone)]
pub struct ProfilerMetricsSummary {
    pub timestamp: u64,

    // Unwinding performance
    pub unwind_success_rate: f64,
    pub avg_unwind_time_us: f64,
    pub max_unwind_time_us: u64,
    pub total_unwind_attempts: u64,

    // Symbol resolution performance
    pub symbol_cache_hit_rate: f64,
    pub symbol_resolution_attempts: u64,

    // Runtime detection performance
    pub runtime_detection_rate: f64,
    pub php_detections: u64,
    pub nodejs_detections: u64,
    pub python_detections: u64,

    // Error metrics
    pub memory_read_failures: u64,
    pub invalid_pointer_accesses: u64,
    pub tail_call_failures: u64,

    // Overall performance
    pub samples_processed: u64,
    pub samples_dropped: u64,
    pub avg_processing_time_us: u64,

    // System metrics
    pub active_processes: u64,
    pub memory_usage_bytes: u64,
}

impl fmt::Display for ProfilerMetricsSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Profiler Metrics Summary (timestamp: {})",
            self.timestamp
        )?;
        writeln!(f, "===============================================")?;
        writeln!(f, "Stack Unwinding:")?;
        writeln!(f, "  Success Rate: {:.2}%", self.unwind_success_rate)?;
        writeln!(f, "  Avg Time: {:.2}μs", self.avg_unwind_time_us)?;
        writeln!(f, "  Max Time: {}μs", self.max_unwind_time_us)?;
        writeln!(f, "  Total Attempts: {}", self.total_unwind_attempts)?;
        writeln!(f)?;
        writeln!(f, "Symbol Resolution:")?;
        writeln!(f, "  Cache Hit Rate: {:.2}%", self.symbol_cache_hit_rate)?;
        writeln!(f, "  Total Attempts: {}", self.symbol_resolution_attempts)?;
        writeln!(f)?;
        writeln!(f, "Runtime Detection:")?;
        writeln!(f, "  Success Rate: {:.2}%", self.runtime_detection_rate)?;
        writeln!(
            f,
            "  PHP: {}, Node.js: {}, Python: {}",
            self.php_detections, self.nodejs_detections, self.python_detections
        )?;
        writeln!(f)?;
        writeln!(f, "Errors:")?;
        writeln!(f, "  Memory Read Failures: {}", self.memory_read_failures)?;
        writeln!(
            f,
            "  Invalid Pointer Access: {}",
            self.invalid_pointer_accesses
        )?;
        writeln!(f, "  Tail Call Failures: {}", self.tail_call_failures)?;
        writeln!(f)?;
        writeln!(f, "Performance:")?;
        writeln!(f, "  Samples Processed: {}", self.samples_processed)?;
        writeln!(f, "  Samples Dropped: {}", self.samples_dropped)?;
        writeln!(
            f,
            "  Avg Processing Time: {}μs",
            self.avg_processing_time_us
        )?;
        writeln!(f, "  Active Processes: {}", self.active_processes)?;
        writeln!(f, "  Memory Usage: {} bytes", self.memory_usage_bytes)?;
        Ok(())
    }
}

/// Performance monitor for tracking operation timings
pub struct PerformanceMonitor {
    start_time: Instant,
    operation_name: String,
    threshold_us: Option<u64>,
    metrics: Arc<ProfilerMetrics>,
}

impl PerformanceMonitor {
    /// Start monitoring an operation
    pub fn start(operation_name: impl Into<String>, metrics: Arc<ProfilerMetrics>) -> Self {
        Self {
            start_time: Instant::now(),
            operation_name: operation_name.into(),
            threshold_us: None,
            metrics,
        }
    }

    /// Start monitoring with performance threshold
    pub fn start_with_threshold(
        operation_name: impl Into<String>,
        threshold_us: u64,
        metrics: Arc<ProfilerMetrics>,
    ) -> Self {
        Self {
            start_time: Instant::now(),
            operation_name: operation_name.into(),
            threshold_us: Some(threshold_us),
            metrics,
        }
    }

    /// Finish monitoring and return duration in microseconds
    pub fn finish(self) -> u64 {
        let duration = self.start_time.elapsed();
        let duration_us = duration.as_micros() as u64;

        // Check threshold if set
        if let Some(threshold) = self.threshold_us {
            if duration_us > threshold {
                warn!(
                    "Performance threshold exceeded for '{}': {}μs > {}μs",
                    self.operation_name, duration_us, threshold
                );
            }
        }

        duration_us
    }

    /// Finish monitoring for stack unwinding operation
    pub fn finish_unwinding(self, success: bool) -> u64 {
        let metrics = self.metrics.clone();
        let duration_us = self.finish();
        metrics.record_unwind_attempt(duration_us, success);
        duration_us
    }
}

/// Health checker for profiler components
pub struct ProfilerHealthChecker {
    metrics: Arc<ProfilerMetrics>,
    last_check: Instant,
    check_interval: Duration,
}

impl ProfilerHealthChecker {
    /// Create new health checker
    pub fn new(metrics: Arc<ProfilerMetrics>) -> Self {
        Self {
            metrics,
            last_check: Instant::now(),
            check_interval: Duration::from_secs(60), // Check every minute
        }
    }

    /// Perform health check and return any issues found
    pub fn check_health(&mut self) -> Vec<String> {
        let now = Instant::now();
        if now.duration_since(self.last_check) < self.check_interval {
            return vec![];
        }

        self.last_check = now;
        let mut issues = Vec::new();

        // Check stack unwinding success rate
        let unwind_rate = self.metrics.get_unwind_success_rate();
        if unwind_rate < 85.0 {
            issues.push(format!(
                "Low stack unwinding success rate: {:.2}%",
                unwind_rate
            ));
        }

        // Check symbol cache hit rate
        let cache_rate = self.metrics.get_symbol_cache_hit_rate();
        if cache_rate < 80.0 {
            issues.push(format!("Low symbol cache hit rate: {:.2}%", cache_rate));
        }

        // Check average unwinding time
        let avg_time = self.metrics.get_avg_unwind_time_us();
        if avg_time > UNWINDING_TIMEOUT_US as f64 {
            issues.push(format!("High average unwinding time: {:.2}μs", avg_time));
        }

        // Check for excessive memory read failures
        let memory_failures = self.metrics.memory_read_failures.load(Ordering::Relaxed);
        let memory_attempts = self.metrics.memory_read_attempts.load(Ordering::Relaxed);
        if memory_attempts > 0 {
            let failure_rate = (memory_failures as f64) / (memory_attempts as f64) * 100.0;
            if failure_rate > 10.0 {
                issues.push(format!(
                    "High memory read failure rate: {:.2}%",
                    failure_rate
                ));
            }
        }

        // Check for tail call failures
        let tail_failures = self.metrics.ebpf_tail_call_failures.load(Ordering::Relaxed);
        let executions = self.metrics.ebpf_program_executions.load(Ordering::Relaxed);
        if executions > 0 {
            let tail_failure_rate = (tail_failures as f64) / (executions as f64) * 100.0;
            if tail_failure_rate > 5.0 {
                issues.push(format!(
                    "High eBPF tail call failure rate: {:.2}%",
                    tail_failure_rate
                ));
            }
        }

        issues
    }

    /// Log health status
    pub fn log_health_status(&mut self) {
        let issues = self.check_health();

        if issues.is_empty() {
            info!("Profiler health check: All systems normal");
        } else {
            warn!("Profiler health check found {} issues:", issues.len());
            for issue in &issues {
                warn!("  - {}", issue);
            }
        }

        // Log metrics summary
        let summary = self.metrics.get_summary();
        debug!(
            "Profiler metrics: unwind_rate={:.2}%, cache_hit_rate={:.2}%, avg_time={:.2}μs",
            summary.unwind_success_rate, summary.symbol_cache_hit_rate, summary.avg_unwind_time_us
        );
    }
}

/// Error context for enhanced debugging
#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub operation: String,
    pub pid: Option<u32>,
    pub runtime_type: Option<u8>,
    pub address: Option<u64>,
    pub additional_info: HashMap<String, String>,
}

impl ErrorContext {
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            pid: None,
            runtime_type: None,
            address: None,
            additional_info: HashMap::new(),
        }
    }

    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn with_runtime(mut self, runtime_type: u8) -> Self {
        self.runtime_type = Some(runtime_type);
        self
    }

    pub fn with_address(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }

    pub fn with_info(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.additional_info.insert(key.into(), value.into());
        self
    }
}

/// Enhanced error logging with context
pub fn log_profiler_error(error: &ProfilerError, context: Option<&ErrorContext>) {
    let context_str = if let Some(ctx) = context {
        format!(
            " [op: {}, pid: {:?}, runtime: {:?}, addr: {:?}]",
            ctx.operation, ctx.pid, ctx.runtime_type, ctx.address
        )
    } else {
        String::new()
    };

    match error {
        ProfilerError::RuntimeDetectionFailed { .. } => {
            warn!("Runtime detection failed{}: {}", context_str, error);
        }
        ProfilerError::InvalidMemoryAccess { .. } => {
            error!("Invalid memory access{}: {}", context_str, error);
        }
        ProfilerError::StackUnwindFailed { .. } => {
            warn!("Stack unwinding failed{}: {}", context_str, error);
        }
        ProfilerError::PerformanceThresholdExceeded { .. } => {
            warn!("Performance threshold exceeded{}: {}", context_str, error);
        }
        _ => {
            debug!("Profiler error{}: {}", context_str, error);
        }
    }
}
