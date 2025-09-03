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

//! Multi-language symbol resolution interface
//!
//! This module provides a unified interface for resolving symbols from
//! different runtime environments including PHP, Node.js/V8, and Python.

use crate::error::Result;
use std::collections::HashMap;
use std::fmt;

/// Runtime type enumeration for symbol resolution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeType {
    Unknown = 0,
    Native = 1,
    PHP = 2,
    NodeJS = 3,
    V8 = 4,
    Python = 5,
}

impl fmt::Display for RuntimeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeType::Unknown => write!(f, "unknown"),
            RuntimeType::Native => write!(f, "native"),
            RuntimeType::PHP => write!(f, "php"),
            RuntimeType::NodeJS => write!(f, "nodejs"),
            RuntimeType::V8 => write!(f, "v8"),
            RuntimeType::Python => write!(f, "python"),
        }
    }
}

/// Unified symbol information across different runtimes
#[derive(Debug, Clone)]
pub struct Symbol {
    pub function_name: String,
    pub file_path: String,
    pub class_or_module: Option<String>,
    pub line_number: u32,
    pub column_number: u32,
    pub frame_type: FrameType,
    pub runtime_type: RuntimeType,
    pub raw_address: u64,
    pub metadata: HashMap<String, String>,
}

impl Symbol {
    pub fn new(function_name: String, file_path: String, runtime_type: RuntimeType) -> Self {
        Self {
            function_name,
            file_path,
            class_or_module: None,
            line_number: 0,
            column_number: 0,
            frame_type: FrameType::User,
            runtime_type,
            raw_address: 0,
            metadata: HashMap::new(),
        }
    }

    /// Format symbol as a human-readable stack frame string
    pub fn format_stack_frame(&self, index: usize) -> String {
        let prefix = match self.runtime_type {
            RuntimeType::PHP => "[php]",
            RuntimeType::NodeJS | RuntimeType::V8 => "[js]",
            RuntimeType::Python => "[py]",
            RuntimeType::Native => "[native]",
            RuntimeType::Unknown => "[unknown]",
        };

        let location = if self.line_number > 0 {
            if self.column_number > 0 {
                format!(
                    "{}:{}:{}",
                    self.file_path, self.line_number, self.column_number
                )
            } else {
                format!("{}:{}", self.file_path, self.line_number)
            }
        } else {
            self.file_path.clone()
        };

        let function_display = if let Some(ref class_or_module) = self.class_or_module {
            format!("{}::{}", class_or_module, self.function_name)
        } else {
            self.function_name.clone()
        };

        format!(
            "{}. {} {} at {}",
            index + 1,
            prefix,
            function_display,
            location
        )
    }

    /// Format symbol in folded stack trace format (for flame graphs)
    pub fn format_folded(&self) -> String {
        let prefix = match self.runtime_type {
            RuntimeType::PHP => "php",
            RuntimeType::NodeJS | RuntimeType::V8 => "js",
            RuntimeType::Python => "py",
            RuntimeType::Native => "",
            RuntimeType::Unknown => "unknown",
        };

        let function_display = if let Some(ref class_or_module) = self.class_or_module {
            format!("{}::{}", class_or_module, self.function_name)
        } else {
            self.function_name.clone()
        };

        if prefix.is_empty() {
            function_display
        } else {
            format!("[{}] {}", prefix, function_display)
        }
    }

    /// Add metadata key-value pair
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Get metadata value by key
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

/// Frame type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    User,     // User-defined functions
    Internal, // Runtime internal functions
    Native,   // C/C++ native functions
    Builtin,  // Language built-in functions
    Unknown,  // Unknown frame type
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameType::User => write!(f, "user"),
            FrameType::Internal => write!(f, "internal"),
            FrameType::Native => write!(f, "native"),
            FrameType::Builtin => write!(f, "builtin"),
            FrameType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Stack trace containing multiple symbols
#[derive(Debug, Clone)]
pub struct StackTrace {
    pub symbols: Vec<Symbol>,
    pub runtime_type: RuntimeType,
    pub process_id: u32,
    pub thread_id: u32,
    pub timestamp: u64,
    pub truncated: bool,
    pub error_message: Option<String>,
}

impl StackTrace {
    pub fn new(runtime_type: RuntimeType, process_id: u32) -> Self {
        Self {
            symbols: Vec::new(),
            runtime_type,
            process_id,
            thread_id: 0,
            timestamp: 0,
            truncated: false,
            error_message: None,
        }
    }

    /// Add a symbol to the stack trace
    pub fn push_symbol(&mut self, symbol: Symbol) {
        self.symbols.push(symbol);
    }

    /// Format entire stack trace as multi-line string
    pub fn format_stack_trace(&self) -> String {
        if self.symbols.is_empty() {
            return "[empty stack trace]".to_string();
        }

        let mut result = String::new();

        // Add header with runtime and process info
        result.push_str(&format!(
            "Stack trace for {} process {} (thread {}):\n",
            self.runtime_type, self.process_id, self.thread_id
        ));

        // Add each symbol
        for (i, symbol) in self.symbols.iter().enumerate() {
            result.push_str(&symbol.format_stack_frame(i));
            result.push('\n');
        }

        // Add footer info
        if self.truncated {
            result.push_str("... (stack trace truncated)\n");
        }

        if let Some(ref error) = self.error_message {
            result.push_str(&format!("Error: {}\n", error));
        }

        result
    }

    /// Format stack trace in folded format for flame graphs
    pub fn format_folded(&self) -> String {
        if self.symbols.is_empty() {
            return "[empty]".to_string();
        }

        // Reverse order for flame graph (root at bottom)
        let folded_frames: Vec<String> = self
            .symbols
            .iter()
            .rev()
            .map(|s| s.format_folded())
            .collect();

        folded_frames.join(";")
    }

    /// Get symbol count
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if stack trace is empty
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

/// Trait for runtime-specific symbol resolvers
pub trait SymbolResolver {
    /// Extract symbols from raw eBPF data
    fn extract_symbols_from_ebpf(&self, raw_data: &[u8]) -> Result<Vec<Symbol>>;

    /// Process and format stack trace
    fn process_stack_trace(&self, pid: u32, symbols: &[Symbol]) -> Result<StackTrace>;

    /// Resolve function name from address (if supported)
    fn resolve_function_name(&self, pid: u32, address: u64) -> Result<Option<String>>;

    /// Get runtime type
    fn runtime_type(&self) -> RuntimeType;

    /// Check if resolver supports given process
    fn supports_process(&self, pid: u32) -> bool;
}

/// Multi-language symbol resolver registry
pub struct SymbolResolverRegistry {
    resolvers: HashMap<RuntimeType, Box<dyn SymbolResolver + Send + Sync>>,
}

impl SymbolResolverRegistry {
    pub fn new() -> Self {
        Self {
            resolvers: HashMap::new(),
        }
    }

    /// Register a symbol resolver for a runtime type
    pub fn register(
        &mut self,
        runtime_type: RuntimeType,
        resolver: Box<dyn SymbolResolver + Send + Sync>,
    ) {
        self.resolvers.insert(runtime_type, resolver);
    }

    /// Get resolver for runtime type
    pub fn get_resolver(
        &self,
        runtime_type: RuntimeType,
    ) -> Option<&(dyn SymbolResolver + Send + Sync)> {
        self.resolvers.get(&runtime_type).map(|r| r.as_ref())
    }

    /// Resolve symbols using appropriate resolver
    pub fn resolve_symbols(
        &self,
        runtime_type: RuntimeType,
        pid: u32,
        raw_data: &[u8],
    ) -> Result<StackTrace> {
        if let Some(resolver) = self.get_resolver(runtime_type) {
            let symbols = resolver.extract_symbols_from_ebpf(raw_data)?;
            resolver.process_stack_trace(pid, &symbols)
        } else {
            // Fallback to generic symbol resolution
            let mut stack_trace = StackTrace::new(RuntimeType::Unknown, pid);
            stack_trace.error_message = Some(format!(
                "No resolver found for runtime type: {}",
                runtime_type
            ));
            Ok(stack_trace)
        }
    }

    /// Auto-detect runtime type and resolve symbols
    pub fn auto_resolve_symbols(&self, pid: u32, raw_data: &[u8]) -> Result<StackTrace> {
        // Try each resolver to see which one supports the process
        for (&_runtime_type, resolver) in &self.resolvers {
            if resolver.supports_process(pid) {
                match resolver.extract_symbols_from_ebpf(raw_data) {
                    Ok(symbols) => {
                        return resolver.process_stack_trace(pid, &symbols);
                    }
                    Err(_) => continue, // Try next resolver
                }
            }
        }

        // No resolver worked
        let mut stack_trace = StackTrace::new(RuntimeType::Unknown, pid);
        stack_trace.error_message = Some("No suitable symbol resolver found".to_string());
        Ok(stack_trace)
    }

    /// Get list of supported runtime types
    pub fn supported_runtimes(&self) -> Vec<RuntimeType> {
        self.resolvers.keys().copied().collect()
    }
}

impl Default for SymbolResolverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for symbol resolution
#[derive(Debug, Clone, Default)]
pub struct SymbolResolverStats {
    pub symbols_resolved: u64,
    pub symbols_failed: u64,
    pub stack_traces_processed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub runtime_detection_time_ns: u64,
    pub symbol_resolution_time_ns: u64,
}

impl SymbolResolverStats {
    pub fn success_rate(&self) -> f64 {
        if self.symbols_resolved + self.symbols_failed > 0 {
            self.symbols_resolved as f64 / (self.symbols_resolved + self.symbols_failed) as f64
        } else {
            0.0
        }
    }

    pub fn cache_hit_rate(&self) -> f64 {
        if self.cache_hits + self.cache_misses > 0 {
            self.cache_hits as f64 / (self.cache_hits + self.cache_misses) as f64
        } else {
            0.0
        }
    }
}
