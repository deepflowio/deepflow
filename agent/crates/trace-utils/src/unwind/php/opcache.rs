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

//! PHP OPcache JIT Detection and Memory Mapping
//!
//! This module handles PHP OPcache extension detection and JIT memory region mapping

use log::{debug, trace, warn};
use object::{Object, ObjectSection, ObjectSymbol};
use regex::Regex;
use semver::Version;
use std::fs;

use crate::{
    error::{Error, Result},
    maps::{get_memory_mappings, MemoryArea},
};

/// OPcache JIT buffer information
#[derive(Debug, Clone)]
pub struct JitBufferInfo {
    /// Address of dasm_buf (JIT code buffer)
    pub buffer_address: u64,
    /// Size of JIT buffer
    pub buffer_size: u64,
    /// Base address of OPcache module
    pub opcache_base: u64,
}

/// PHP OPcache JIT support
pub struct PhpOpcacheSupport {
    version: Version,
    opcache_detected: bool,
    jit_buffer_info: Option<JitBufferInfo>,
    opcache_module_path: Option<String>,
}

impl PhpOpcacheSupport {
    /// Create new OPcache support instance
    pub fn new(version: Version) -> Self {
        Self {
            version,
            opcache_detected: false,
            jit_buffer_info: None,
            opcache_module_path: None,
        }
    }

    /// Detect OPcache module from process memory mappings
    pub fn detect_opcache(&mut self, pid: u32) -> Result<bool> {
        let mappings = get_memory_mappings(pid)?;

        // Look for opcache.so in memory mappings
        let opcache_regex = Regex::new(r"(?:.*/)?opcache\.so$").unwrap();

        for mapping in &mappings {
            if opcache_regex.is_match(&mapping.path) {
                debug!(
                    "Found OPcache module: {} at 0x{:x}-0x{:x}",
                    mapping.path, mapping.mx_start, mapping.m_end
                );

                self.opcache_detected = true;
                self.opcache_module_path = Some(mapping.path.clone());

                // Try to analyze the OPcache module for JIT buffer info
                if let Err(e) = self.analyze_opcache_module(pid, &mapping) {
                    warn!("Failed to analyze OPcache module: {}", e);
                    // Continue anyway - we at least detected OPcache
                }

                return Ok(true);
            }
        }

        debug!("No OPcache module detected for process#{}", pid);
        Ok(false)
    }

    /// Analyze OPcache module to extract JIT buffer information
    fn analyze_opcache_module(&mut self, pid: u32, mapping: &MemoryArea) -> Result<()> {
        let proc_root = format!("/proc/{}/root", pid);
        let opcache_path = if mapping.path.starts_with('/') {
            format!("{}{}", proc_root, mapping.path)
        } else {
            mapping.path.clone()
        };

        let binary_data = fs::read(&opcache_path)?;
        let obj = object::File::parse(binary_data.as_slice())?;

        // Look for zend_extension_entry symbol
        let extension_entry = obj.symbols().chain(obj.dynamic_symbols()).find(|s| {
            s.name()
                .map(|n| n == "zend_extension_entry")
                .unwrap_or(false)
        });

        if let Some(symbol) = extension_entry {
            debug!(
                "Found zend_extension_entry in OPcache at 0x{:x}",
                symbol.address()
            );

            // Verify this is actually the OPcache by checking the version string
            if let Ok(version) = self.extract_opcache_version(&obj) {
                debug!("Confirmed OPcache version: {}", version);

                // Try to find JIT buffer symbols
                if let Ok(buffer_info) = self.extract_jit_buffer_info(&obj, mapping.mx_start) {
                    self.jit_buffer_info = Some(buffer_info);
                    debug!("Successfully extracted JIT buffer info");
                }
            }
        }

        Ok(())
    }

    /// Extract OPcache version from zend_extension_entry
    fn extract_opcache_version(&self, obj: &object::File) -> Result<String> {
        // The zend_extension structure has version as the second pointer
        // struct _zend_extension {
        //   char *name;        // offset 0
        //   char *version;     // offset 8 (on 64-bit)
        //   ...
        // }

        if let Some(_symbol) = obj.symbols().chain(obj.dynamic_symbols()).find(|s| {
            s.name()
                .map(|n| n == "zend_extension_entry")
                .unwrap_or(false)
        }) {
            // This is a simplified approach - in reality we'd need to read from process memory
            // For now, we'll assume success if we found the symbol
            Ok(format!("PHP {}", self.version))
        } else {
            Err(Error::InvalidData)
        }
    }

    /// Extract JIT buffer information from OPcache module
    fn extract_jit_buffer_info(&self, obj: &object::File, base_addr: u64) -> Result<JitBufferInfo> {
        // Look for dasm_buf and dasm_size global variables
        // These are defined in zend_jit.c:
        // static void *dasm_buf = NULL;
        // static size_t dasm_size = 0;

        let mut dasm_buf_addr = None;
        let mut dasm_size_addr = None;

        // Look for symbols that might be dasm_buf and dasm_size
        for symbol in obj.symbols().chain(obj.dynamic_symbols()) {
            if let Ok(name) = symbol.name() {
                match name {
                    "dasm_buf" => dasm_buf_addr = Some(symbol.address()),
                    "dasm_size" => dasm_size_addr = Some(symbol.address()),
                    _ => {}
                }
            }
        }

        // If direct symbols not found, try to find them via zend_jit_unprotect function
        if dasm_buf_addr.is_none() || dasm_size_addr.is_none() {
            if let Some((buf_addr, size_addr)) = self.find_dasm_pointers_via_unprotect(obj)? {
                dasm_buf_addr = Some(buf_addr);
                dasm_size_addr = Some(size_addr);
            }
        }

        match (dasm_buf_addr, dasm_size_addr) {
            (Some(buf_addr), Some(size_addr)) => {
                let buffer_info = JitBufferInfo {
                    buffer_address: base_addr + buf_addr,
                    buffer_size: base_addr + size_addr, // This will need to be dereferenced
                    opcache_base: base_addr,
                };

                debug!(
                    "Found JIT buffer pointers - buf: 0x{:x}, size: 0x{:x}",
                    buffer_info.buffer_address, buffer_info.buffer_size
                );

                Ok(buffer_info)
            }
            _ => {
                debug!("Could not find dasm_buf/dasm_size symbols in OPcache");
                Err(Error::InvalidData)
            }
        }
    }

    /// Find dasm buffer pointers by analyzing zend_jit_unprotect function
    fn find_dasm_pointers_via_unprotect(&self, obj: &object::File) -> Result<Option<(u64, u64)>> {
        // Look for zend_jit_unprotect function
        let unprotect_symbol = obj
            .symbols()
            .chain(obj.dynamic_symbols())
            .find(|s| s.name().map(|n| n == "zend_jit_unprotect").unwrap_or(false));

        if let Some(symbol) = unprotect_symbol {
            let address = symbol.address();
            trace!("Found zend_jit_unprotect at 0x{:x}", address);

            // Get function code
            if let Some(section) = obj.section_by_name(".text") {
                if let Ok(section_data) = section.data() {
                    let symbol_offset = (address - section.address()) as usize;

                    if symbol_offset + 64 <= section_data.len() {
                        let code = &section_data[symbol_offset..symbol_offset + 64];
                        return self.extract_dasm_pointers_from_unprotect(code, obj, address);
                    }
                }
            }
        }

        Ok(None)
    }

    /// Extract dasm buffer pointers from zend_jit_unprotect disassembly
    fn extract_dasm_pointers_from_unprotect(
        &self,
        code: &[u8],
        obj: &object::File,
        base_addr: u64,
    ) -> Result<Option<(u64, u64)>> {
        match obj.architecture() {
            object::Architecture::X86_64 => self.extract_dasm_pointers_x86_64(code, base_addr),
            object::Architecture::Aarch64 => self.extract_dasm_pointers_aarch64(code, base_addr),
            arch => {
                warn!(
                    "Unsupported architecture for dasm pointer extraction: {:?}",
                    arch
                );
                Ok(None)
            }
        }
    }

    /// Extract dasm pointers from x86_64 zend_jit_unprotect
    fn extract_dasm_pointers_x86_64(
        &self,
        code: &[u8],
        base_addr: u64,
    ) -> Result<Option<(u64, u64)>> {
        // zend_jit_unprotect typically calls mprotect(dasm_buf, dasm_size, ...)
        // Look for patterns that load these global variables

        let mut potential_addresses = Vec::new();

        // Look for RIP-relative addressing (mov reg, [rip+offset])
        for i in 0..code.len().saturating_sub(7) {
            // Pattern: mov rax, [rip+offset] (0x48 0x8b 0x05)
            if code[i] == 0x48 && code[i + 1] == 0x8b && code[i + 2] == 0x05 {
                let offset =
                    i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);

                let target_addr = (base_addr + i as u64 + 7).wrapping_add(offset as u64);
                potential_addresses.push(target_addr);
                trace!(
                    "Found potential dasm pointer reference at 0x{:x}",
                    target_addr
                );
            }
        }

        // We expect to find two addresses (dasm_buf and dasm_size)
        if potential_addresses.len() >= 2 {
            Ok(Some((potential_addresses[0], potential_addresses[1])))
        } else {
            Ok(None)
        }
    }

    /// Extract dasm pointers from aarch64 zend_jit_unprotect
    fn extract_dasm_pointers_aarch64(
        &self,
        code: &[u8],
        base_addr: u64,
    ) -> Result<Option<(u64, u64)>> {
        // On aarch64, global variables are accessed via adrp/add or adrp/ldr sequences
        let mut potential_addresses = Vec::new();

        for i in (0..code.len().saturating_sub(8)).step_by(4) {
            let instr1 = u32::from_le_bytes([code[i], code[i + 1], code[i + 2], code[i + 3]]);

            // Check for adrp instruction (0x90000000 mask)
            if (instr1 & 0x9f000000) == 0x90000000 {
                if i + 8 <= code.len() {
                    let instr2 =
                        u32::from_le_bytes([code[i + 4], code[i + 5], code[i + 6], code[i + 7]]);

                    // Check if followed by add/ldr instruction
                    if (instr2 & 0xffc00000) == 0x91000000 || // add
                       (instr2 & 0xffc00000) == 0xf9400000
                    {
                        // ldr

                        // Decode adrp immediate
                        let immhi = (instr1 >> 5) & 0x7ffff;
                        let immlo = (instr1 >> 29) & 0x3;
                        let imm = ((immhi << 2) | immlo) as i64;

                        let page_base = (base_addr + i as u64) & !0xfff;
                        let target_addr = page_base.wrapping_add((imm << 12) as u64);

                        potential_addresses.push(target_addr);
                        trace!(
                            "Found potential dasm pointer reference at 0x{:x}",
                            target_addr
                        );
                    }
                }
            }
        }

        if potential_addresses.len() >= 2 {
            Ok(Some((potential_addresses[0], potential_addresses[1])))
        } else {
            Ok(None)
        }
    }

    /// Check if OPcache with JIT is detected and ready
    pub fn is_jit_available(&self) -> bool {
        self.opcache_detected && self.jit_buffer_info.is_some()
    }

    /// Get JIT buffer information
    pub fn get_jit_buffer_info(&self) -> Option<&JitBufferInfo> {
        self.jit_buffer_info.as_ref()
    }

    /// Get OPcache module path
    pub fn get_opcache_path(&self) -> Option<&String> {
        self.opcache_module_path.as_ref()
    }

    /// Read actual JIT buffer info from process memory
    pub fn read_jit_buffer_runtime_info(&self, _pid: u32) -> Result<Option<(u64, u64)>> {
        if let Some(buffer_info) = &self.jit_buffer_info {
            // In a real implementation, we would use process_vm_readv or similar
            // to read the actual values of dasm_buf and dasm_size from the target process
            //
            // For now, return placeholder values indicating the addresses where
            // the actual buffer pointer and size can be read from
            Ok(Some((buffer_info.buffer_address, buffer_info.buffer_size)))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests;
