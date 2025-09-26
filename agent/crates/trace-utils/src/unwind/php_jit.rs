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

//! PHP JIT Support Module
//!
//! This module implements PHP 8+ JIT compilation support for profiling,
//! based on the OpenTelemetry eBPF profiler approach.

use log::{debug, trace, warn};
use object::{Object, ObjectSection, ObjectSymbol};
use semver::Version;

use crate::error::Result;

// PHP VM Kind constants from Zend/zend_vm_opcodes.h
const ZEND_VM_KIND_HYBRID: u32 = 1 << 2; // JIT-compatible mode (same as GOTO)

/// PHP JIT profiling support
pub struct PhpJitSupport {
    version: Version,
    vm_kind: Option<u32>,
    jit_return_address: Option<u64>,
    execute_ex_address: Option<u64>,
}

impl PhpJitSupport {
    /// Create new PHP JIT support instance
    pub fn new(version: Version) -> Self {
        Self {
            version,
            vm_kind: None,
            jit_return_address: None,
            execute_ex_address: None,
        }
    }

    /// Check if this PHP version supports JIT
    pub fn supports_jit(&self) -> bool {
        self.version >= Version::new(8, 0, 0)
    }

    /// Determine VM kind by analyzing zend_vm_kind function
    pub fn determine_vm_kind(&mut self, binary_data: &[u8]) -> Result<u32> {
        if !self.supports_jit() {
            return Ok(0); // No JIT support for PHP < 8.0
        }

        let obj = object::File::parse(binary_data)?;

        // Find zend_vm_kind symbol
        let zend_vm_kind_symbol = obj
            .symbols()
            .chain(obj.dynamic_symbols())
            .find(|s| s.name().map(|n| n == "zend_vm_kind").unwrap_or(false));

        if let Some(symbol) = zend_vm_kind_symbol {
            let address = symbol.address();
            trace!("Found zend_vm_kind symbol at address: 0x{:x}", address);

            // Read function code (should be very short - just a mov and ret)
            if let Some(section) = obj.section_by_name(".text") {
                if let Ok(section_data) = section.data() {
                    let symbol_offset = (address - section.address()) as usize;

                    if symbol_offset + 64 <= section_data.len() {
                        let code = &section_data[symbol_offset..symbol_offset + 64];
                        let vm_kind = self.extract_vm_kind_from_code(code, &obj)?;
                        self.vm_kind = Some(vm_kind);
                        debug!("Detected VM kind: 0x{:x}", vm_kind);
                        return Ok(vm_kind);
                    }
                }
            }
        }

        warn!("Could not determine VM kind for PHP {}", self.version);
        Ok(0)
    }

    /// Extract VM kind from zend_vm_kind function code
    fn extract_vm_kind_from_code(&self, code: &[u8], obj: &object::File) -> Result<u32> {
        match obj.architecture() {
            object::Architecture::X86_64 => self.extract_vm_kind_x86_64(code),
            object::Architecture::Aarch64 => self.extract_vm_kind_aarch64(code),
            arch => {
                warn!("Unsupported architecture for VM kind detection: {:?}", arch);
                Ok(0)
            }
        }
    }

    /// Extract VM kind from x86_64 assembly
    fn extract_vm_kind_x86_64(&self, code: &[u8]) -> Result<u32> {
        // Look for pattern: mov eax, <immediate>; ret
        // zend_vm_kind() should be a simple function returning a constant

        for i in 0..code.len().saturating_sub(6) {
            // Pattern: mov eax, imm32 (0xb8 followed by 4-byte immediate)
            if code[i] == 0xb8 {
                let vm_kind =
                    u32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);

                // Check if followed by ret (0xc3)
                if i + 5 < code.len() && code[i + 5] == 0xc3 {
                    trace!("Found VM kind from x86_64 assembly: 0x{:x}", vm_kind);
                    return Ok(vm_kind);
                }
            }
        }

        Ok(0)
    }

    /// Extract VM kind from aarch64 assembly
    fn extract_vm_kind_aarch64(&self, code: &[u8]) -> Result<u32> {
        // Look for pattern: mov w0, #<immediate>; ret
        // On aarch64, constants are loaded differently

        for i in 0..code.len().saturating_sub(3) {
            // Pattern: mov w0, #imm16 (can be multiple instructions for larger constants)
            // This is a simplified check - real implementation would need full aarch64 decoding

            // Look for return instruction (0xd65f03c0)
            let ret_bytes = [0xc0, 0x03, 0x5f, 0xd6];
            if i + 4 <= code.len() && &code[i..i + 4] == ret_bytes {
                // Look backwards for mov instruction
                // This is a simplified heuristic
                if i >= 4 {
                    let prev_instr =
                        u32::from_le_bytes([code[i - 4], code[i - 3], code[i - 2], code[i - 1]]);

                    // Check if this looks like a mov w0, #imm instruction
                    // Format: 0x52800000 | (imm16 << 5)
                    if (prev_instr & 0xffe00000) == 0x52800000 {
                        let vm_kind = (prev_instr >> 5) & 0xffff;
                        trace!("Found VM kind from aarch64 assembly: 0x{:x}", vm_kind);
                        return Ok(vm_kind);
                    }
                }
                break;
            }
        }

        Ok(0)
    }

    /// Recover JIT return address by analyzing execute_ex function
    pub fn recover_jit_return_address(&mut self, binary_data: &[u8]) -> Result<u64> {
        if !self.supports_jit() {
            return Ok(0);
        }

        // First determine VM kind
        let vm_kind = self.determine_vm_kind(binary_data)?;

        // Check VM kind - prefer HYBRID mode but allow other modes for JIT
        if vm_kind == ZEND_VM_KIND_HYBRID {
            // Optimal for JIT
        } else if vm_kind != 0 {
            // Not HYBRID but proceeding with JIT recovery
        } else {
            // Could not determine VM kind, proceeding with JIT recovery anyway
        }

        let obj = object::File::parse(binary_data)?;

        // Find execute_ex symbol
        let execute_ex_symbol = obj
            .symbols()
            .chain(obj.dynamic_symbols())
            .find(|s| s.name().map(|n| n == "execute_ex").unwrap_or(false));

        if let Some(symbol) = execute_ex_symbol {
            let address = symbol.address();
            self.execute_ex_address = Some(address);
            trace!("Found execute_ex symbol at address: 0x{:x}", address);

            // Read first 128 bytes of execute_ex function
            if let Some(section) = obj.section_by_name(".text") {
                if let Ok(section_data) = section.data() {
                    let symbol_offset = (address - section.address()) as usize;

                    if symbol_offset + 128 <= section_data.len() {
                        let code = &section_data[symbol_offset..symbol_offset + 128];
                        let return_addr = self.extract_jit_return_address(code, &obj, address)?;
                        self.jit_return_address = Some(return_addr);
                        debug!("Recovered JIT return address: 0x{:x}", return_addr);
                        return Ok(return_addr);
                    }
                }
            }
        }

        warn!(
            "Could not recover JIT return address for PHP {}",
            self.version
        );
        Ok(0)
    }

    /// Extract JIT return address from execute_ex function code
    fn extract_jit_return_address(
        &self,
        code: &[u8],
        obj: &object::File,
        base_addr: u64,
    ) -> Result<u64> {
        match obj.architecture() {
            object::Architecture::X86_64 => self.extract_jit_return_address_x86_64(code, base_addr),
            object::Architecture::Aarch64 => {
                self.extract_jit_return_address_aarch64(code, base_addr)
            }
            arch => {
                warn!(
                    "Unsupported architecture for JIT return address extraction: {:?}",
                    arch
                );
                Ok(0)
            }
        }
    }

    /// Extract JIT return address from x86_64 execute_ex
    fn extract_jit_return_address_x86_64(&self, code: &[u8], base_addr: u64) -> Result<u64> {
        // Look for jump table pattern in execute_ex
        // The JIT return address is typically found after a specific pattern
        // This is a simplified implementation - the actual pattern varies by PHP version

        // Look for indirect jump instructions (0xff, 0x25 for jmp [rip+offset])
        for i in 0..code.len().saturating_sub(8) {
            if code[i] == 0xff && code[i + 1] == 0x25 {
                // Found jmp [rip+offset]
                let offset =
                    i32::from_le_bytes([code[i + 2], code[i + 3], code[i + 4], code[i + 5]]);

                // Calculate the address this jump refers to
                let jump_target = (base_addr + i as u64 + 6).wrapping_add(offset as u64);

                // The next instruction after this jump could be our return address
                if i + 6 < code.len() {
                    let return_addr = base_addr + (i + 6) as u64;
                    trace!(
                        "Found potential JIT return address at 0x{:x} (jump target: 0x{:x})",
                        return_addr,
                        jump_target
                    );
                    return Ok(return_addr);
                }
            }
        }

        // Fallback: look for a mov instruction followed by jmp
        for i in 0..code.len().saturating_sub(16) {
            // Look for mov rax, imm64 followed by jmp patterns
            if code[i] == 0x48 && code[i + 1] == 0xb8 {
                // mov rax, imm64
                let imm64 = u64::from_le_bytes([
                    code[i + 2],
                    code[i + 3],
                    code[i + 4],
                    code[i + 5],
                    code[i + 6],
                    code[i + 7],
                    code[i + 8],
                    code[i + 9],
                ]);

                // Check if followed by a jump instruction
                if i + 10 < code.len() && (code[i + 10] == 0xff || code[i + 10] == 0xe9) {
                    let return_addr = base_addr + (i + 10) as u64;
                    trace!(
                        "Found JIT return address pattern at 0x{:x} (imm64: 0x{:x})",
                        return_addr,
                        imm64
                    );
                    return Ok(return_addr);
                }
            }
        }

        Ok(0)
    }

    /// Extract JIT return address from aarch64 execute_ex
    fn extract_jit_return_address_aarch64(&self, code: &[u8], base_addr: u64) -> Result<u64> {
        // Look for branch patterns in aarch64 execute_ex
        // This is more complex due to aarch64's different instruction encoding

        for i in (0..code.len().saturating_sub(4)).step_by(4) {
            let instr = u32::from_le_bytes([code[i], code[i + 1], code[i + 2], code[i + 3]]);

            // Check for branch instructions (simplified)
            // b <target>: 0x14000000 | (imm26 << 0)
            // bl <target>: 0x94000000 | (imm26 << 0)
            if (instr & 0xfc000000) == 0x14000000 || (instr & 0xfc000000) == 0x94000000 {
                let offset = ((instr & 0x03ffffff) as i32) << 2;
                let jump_target = (base_addr + i as u64).wrapping_add(offset as u64);

                // The instruction after this branch could be our return address
                if i + 8 < code.len() {
                    let return_addr = base_addr + (i + 8) as u64;
                    trace!(
                        "Found potential JIT return address at 0x{:x} (jump target: 0x{:x})",
                        return_addr,
                        jump_target
                    );
                    return Ok(return_addr);
                }
            }
        }

        Ok(0)
    }

    /// Get the recovered JIT return address
    pub fn get_jit_return_address(&self) -> Option<u64> {
        self.jit_return_address
    }

    /// Get the VM kind
    pub fn get_vm_kind(&self) -> Option<u32> {
        self.vm_kind
    }

    /// Check if JIT is supported and properly configured
    pub fn is_jit_ready(&self) -> bool {
        self.supports_jit()
            && self.vm_kind == Some(ZEND_VM_KIND_HYBRID)
            && self.jit_return_address.is_some()
            && self.jit_return_address.unwrap() != 0
    }
}

#[cfg(test)]
#[path = "php_jit/tests.rs"]
mod tests;
