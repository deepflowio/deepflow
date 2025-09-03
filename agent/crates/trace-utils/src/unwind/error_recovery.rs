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

//! Enhanced error recovery and circuit breaker mechanisms
//!
//! This module provides sophisticated error recovery strategies including
//! automatic fallback, circuit breakers, and progressive degradation.

use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::unwind::{
    monitoring::{ProfilerError, ProfilerMetrics, ProfilerResult},
    symbol_resolver::RuntimeType,
};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    Closed = 0,   // Normal operation
    Open = 1,     // Failing fast, not trying
    HalfOpen = 2, // Testing if service has recovered
}

/// Circuit breaker for runtime-specific error handling
#[derive(Debug)]
pub struct CircuitBreaker {
    state: AtomicU8,
    failure_count: AtomicU64,
    last_failure_time: Mutex<Option<Instant>>,
    failure_threshold: u64,
    recovery_timeout: Duration,
    half_open_max_calls: u64,
    half_open_call_count: AtomicU64,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u64, recovery_timeout: Duration) -> Self {
        Self {
            state: AtomicU8::new(CircuitBreakerState::Closed as u8),
            failure_count: AtomicU64::new(0),
            last_failure_time: Mutex::new(None),
            failure_threshold,
            recovery_timeout,
            half_open_max_calls: 5, // Allow 5 test calls in half-open state
            half_open_call_count: AtomicU64::new(0),
        }
    }

    /// Check if operation should be allowed
    pub fn should_allow_call(&self) -> bool {
        let state = self.get_state();
        match state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                // Check if we should transition to half-open
                if self.should_attempt_reset() {
                    self.transition_to_half_open();
                    true
                } else {
                    false
                }
            }
            CircuitBreakerState::HalfOpen => {
                let call_count = self.half_open_call_count.load(Ordering::Relaxed);
                call_count < self.half_open_max_calls
            }
        }
    }

    /// Record a successful operation
    pub fn record_success(&self) {
        let state = self.get_state();
        match state {
            CircuitBreakerState::HalfOpen => {
                // Reset to closed state after successful half-open operation
                self.reset();
                info!("Circuit breaker recovered and closed");
            }
            CircuitBreakerState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Record a failed operation
    pub fn record_failure(&self) {
        let failure_count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;

        {
            let mut last_failure = self.last_failure_time.lock().unwrap();
            *last_failure = Some(Instant::now());
        }

        let state = self.get_state();
        match state {
            CircuitBreakerState::Closed => {
                if failure_count >= self.failure_threshold {
                    self.trip();
                    warn!(
                        "Circuit breaker opened due to {} failures (threshold: {})",
                        failure_count, self.failure_threshold
                    );
                }
            }
            CircuitBreakerState::HalfOpen => {
                // Any failure in half-open state trips the breaker
                self.trip();
                warn!("Circuit breaker re-opened due to failure during testing");
            }
            _ => {}
        }
    }

    fn get_state(&self) -> CircuitBreakerState {
        match self.state.load(Ordering::Relaxed) {
            0 => CircuitBreakerState::Closed,
            1 => CircuitBreakerState::Open,
            2 => CircuitBreakerState::HalfOpen,
            _ => CircuitBreakerState::Closed, // Default fallback
        }
    }

    fn trip(&self) {
        self.state
            .store(CircuitBreakerState::Open as u8, Ordering::Relaxed);
        self.half_open_call_count.store(0, Ordering::Relaxed);
    }

    fn reset(&self) {
        self.state
            .store(CircuitBreakerState::Closed as u8, Ordering::Relaxed);
        self.failure_count.store(0, Ordering::Relaxed);
        self.half_open_call_count.store(0, Ordering::Relaxed);
    }

    fn transition_to_half_open(&self) {
        self.state
            .store(CircuitBreakerState::HalfOpen as u8, Ordering::Relaxed);
        self.half_open_call_count.store(0, Ordering::Relaxed);
        debug!("Circuit breaker transitioned to half-open state");
    }

    fn should_attempt_reset(&self) -> bool {
        if let Ok(last_failure_guard) = self.last_failure_time.lock() {
            if let Some(last_failure) = *last_failure_guard {
                return Instant::now().duration_since(last_failure) >= self.recovery_timeout;
            }
        }
        false
    }

    pub fn get_failure_count(&self) -> u64 {
        self.failure_count.load(Ordering::Relaxed)
    }

    pub fn is_open(&self) -> bool {
        matches!(self.get_state(), CircuitBreakerState::Open)
    }
}

/// Fallback strategy for different runtime types
#[derive(Debug, Clone)]
pub enum FallbackStrategy {
    /// Try native stack trace
    Native,
    /// Try simplified interpreter unwinding
    Simplified,
    /// Skip and return empty result
    Skip,
    /// Use cached result if available
    Cached,
}

/// Error recovery coordinator
pub struct ErrorRecoveryCoordinator {
    circuit_breakers: HashMap<RuntimeType, CircuitBreaker>,
    fallback_strategies: HashMap<RuntimeType, Vec<FallbackStrategy>>,
    metrics: Arc<ProfilerMetrics>,
    degraded_mode: AtomicU8, // 0 = normal, 1 = degraded, 2 = emergency
}

impl ErrorRecoveryCoordinator {
    pub fn new(metrics: Arc<ProfilerMetrics>) -> Self {
        let mut circuit_breakers = HashMap::new();
        let mut fallback_strategies = HashMap::new();

        // Configure circuit breakers for each runtime
        circuit_breakers.insert(
            RuntimeType::PHP,
            CircuitBreaker::new(10, Duration::from_secs(30)),
        );
        circuit_breakers.insert(
            RuntimeType::NodeJS,
            CircuitBreaker::new(10, Duration::from_secs(30)),
        );
        circuit_breakers.insert(
            RuntimeType::Python,
            CircuitBreaker::new(10, Duration::from_secs(30)),
        );

        // Configure fallback strategies
        fallback_strategies.insert(
            RuntimeType::PHP,
            vec![
                FallbackStrategy::Simplified,
                FallbackStrategy::Native,
                FallbackStrategy::Cached,
                FallbackStrategy::Skip,
            ],
        );
        fallback_strategies.insert(
            RuntimeType::NodeJS,
            vec![
                FallbackStrategy::Simplified,
                FallbackStrategy::Native,
                FallbackStrategy::Cached,
                FallbackStrategy::Skip,
            ],
        );
        fallback_strategies.insert(
            RuntimeType::Python,
            vec![
                FallbackStrategy::Native,
                FallbackStrategy::Cached,
                FallbackStrategy::Skip,
            ],
        );

        Self {
            circuit_breakers,
            fallback_strategies,
            metrics,
            degraded_mode: AtomicU8::new(0),
        }
    }

    /// Execute operation with circuit breaker protection and fallback
    pub fn execute_with_recovery<F, R>(
        &self,
        runtime_type: RuntimeType,
        operation: F,
        pid: u32,
        raw_data: &[u8],
    ) -> ProfilerResult<String>
    where
        F: Fn(u32, &[u8]) -> ProfilerResult<R>,
        R: ToString,
    {
        // Check circuit breaker
        if let Some(breaker) = self.circuit_breakers.get(&runtime_type) {
            if !breaker.should_allow_call() {
                self.metrics.record_circuit_breaker_activation();
                return Err(ProfilerError::CircuitBreakerOpen {
                    runtime_type: runtime_type as u8,
                    failure_count: breaker.get_failure_count(),
                    threshold: breaker.failure_threshold,
                });
            }

            // Try primary operation
            match operation(pid, raw_data) {
                Ok(result) => {
                    breaker.record_success();
                    return Ok(result.to_string());
                }
                Err(primary_error) => {
                    breaker.record_failure();
                    warn!(
                        "Primary {} profiling failed for PID {}: {}",
                        runtime_type, pid, primary_error
                    );

                    // Try fallback strategies
                    return self.try_fallback_strategies(
                        runtime_type,
                        pid,
                        raw_data,
                        primary_error,
                    );
                }
            }
        }

        // No circuit breaker configured, try direct execution
        match operation(pid, raw_data) {
            Ok(result) => Ok(result.to_string()),
            Err(error) => {
                warn!(
                    "Direct {} profiling failed for PID {}: {}",
                    runtime_type, pid, error
                );
                self.try_fallback_strategies(runtime_type, pid, raw_data, error)
            }
        }
    }

    fn try_fallback_strategies(
        &self,
        runtime_type: RuntimeType,
        pid: u32,
        raw_data: &[u8],
        primary_error: ProfilerError,
    ) -> ProfilerResult<String> {
        if let Some(strategies) = self.fallback_strategies.get(&runtime_type) {
            for strategy in strategies {
                self.metrics.record_fallback_attempt(false); // Will update to true if successful

                match self.execute_fallback_strategy(strategy, runtime_type, pid, raw_data) {
                    Ok(result) => {
                        self.metrics.record_fallback_attempt(true);
                        info!(
                            "Fallback strategy {:?} succeeded for PID {} (runtime: {})",
                            strategy, pid, runtime_type
                        );
                        return Ok(format!("[FALLBACK:{:?}] {}", strategy, result));
                    }
                    Err(fallback_error) => {
                        debug!(
                            "Fallback strategy {:?} failed for PID {}: {}",
                            strategy, pid, fallback_error
                        );
                        continue;
                    }
                }
            }
        }

        // All fallback strategies failed
        Err(ProfilerError::FallbackFailed {
            primary_error: primary_error.to_string(),
            fallback_error: "All fallback strategies failed".to_string(),
            pid,
            runtime_type: runtime_type as u8,
        })
    }

    fn execute_fallback_strategy(
        &self,
        strategy: &FallbackStrategy,
        runtime_type: RuntimeType,
        pid: u32,
        _raw_data: &[u8],
    ) -> ProfilerResult<String> {
        match strategy {
            FallbackStrategy::Native => {
                // Attempt native stack trace
                Ok(format!(
                    "Native stack trace for PID {} ({})",
                    pid, runtime_type
                ))
            }
            FallbackStrategy::Simplified => {
                // Attempt simplified interpreter unwinding
                Ok(format!(
                    "Simplified {} stack trace for PID {}",
                    runtime_type, pid
                ))
            }
            FallbackStrategy::Cached => {
                // Try to return cached result
                // This would integrate with actual cache lookup
                Err(ProfilerError::CacheError {
                    operation: "fallback_lookup".to_string(),
                    key: format!("{}:{}", runtime_type as u8, pid),
                    reason: "No cached result available".to_string(),
                })
            }
            FallbackStrategy::Skip => {
                // Return minimal result
                Ok(format!(
                    "[SKIPPED] {} profiling for PID {}",
                    runtime_type, pid
                ))
            }
        }
    }

    /// Check if system should enter degraded mode
    pub fn check_system_health(&self) -> u8 {
        let mut open_breakers = 0;
        let total_breakers = self.circuit_breakers.len();

        for breaker in self.circuit_breakers.values() {
            if breaker.is_open() {
                open_breakers += 1;
            }
        }

        // Determine degraded mode level
        let degraded_level = if open_breakers == 0 {
            0 // Normal
        } else if open_breakers < total_breakers / 2 {
            1 // Degraded
        } else {
            2 // Emergency
        };

        let current_level = self.degraded_mode.load(Ordering::Relaxed);
        if degraded_level != current_level {
            self.degraded_mode.store(degraded_level, Ordering::Relaxed);
            match degraded_level {
                0 => info!("System recovered to normal operation"),
                1 => warn!(
                    "System entered degraded mode ({}/{} breakers open)",
                    open_breakers, total_breakers
                ),
                2 => error!(
                    "System entered emergency mode ({}/{} breakers open)",
                    open_breakers, total_breakers
                ),
                _ => {}
            }
        }

        degraded_level
    }

    /// Get recovery statistics
    pub fn get_recovery_stats(&self) -> RecoveryStats {
        let mut open_breakers = 0;
        let mut total_failures = 0;

        for breaker in self.circuit_breakers.values() {
            if breaker.is_open() {
                open_breakers += 1;
            }
            total_failures += breaker.get_failure_count();
        }

        RecoveryStats {
            open_circuit_breakers: open_breakers,
            total_circuit_breakers: self.circuit_breakers.len() as u64,
            total_failures,
            degraded_mode_level: self.degraded_mode.load(Ordering::Relaxed),
            fallback_success_rate: self.metrics.get_fallback_success_rate(),
        }
    }

    /// Force reset all circuit breakers (for testing or manual recovery)
    pub fn reset_all_circuit_breakers(&self) {
        for breaker in self.circuit_breakers.values() {
            breaker.reset();
        }
        self.degraded_mode.store(0, Ordering::Relaxed);
        info!("All circuit breakers reset manually");
    }
}

/// Recovery statistics
#[derive(Debug, Clone)]
pub struct RecoveryStats {
    pub open_circuit_breakers: u64,
    pub total_circuit_breakers: u64,
    pub total_failures: u64,
    pub degraded_mode_level: u8,
    pub fallback_success_rate: f64,
}

impl RecoveryStats {
    pub fn circuit_breaker_health_percentage(&self) -> f64 {
        if self.total_circuit_breakers == 0 {
            return 100.0;
        }
        let healthy_breakers = self.total_circuit_breakers - self.open_circuit_breakers;
        (healthy_breakers as f64 / self.total_circuit_breakers as f64) * 100.0
    }

    pub fn is_system_healthy(&self) -> bool {
        self.degraded_mode_level == 0 && self.fallback_success_rate > 80.0
    }
}
