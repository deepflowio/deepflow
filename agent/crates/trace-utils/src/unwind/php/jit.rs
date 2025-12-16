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
//! This module implements PHP 8+ JIT compilation support for profiling

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
    ///
    /// Find the first JMP instruction
    /// in execute_ex and return the address right after it (the return address).
    /// Since all JIT code is ultimately called from execute_ex, this is the
    /// return address for all JIT code.
    fn extract_jit_return_address_x86_64(&self, code: &[u8], base_addr: u64) -> Result<u64> {
        // Scan through the code looking for JMP instructions
        // Common JMP encodings in x86-64:
        // - 0xff /4: jmp r/m64 (indirect jump through register or memory)
        //   - 0xff 0xe0: jmp rax
        //   - 0xff 0x25: jmp [rip+offset]
        // - 0xe9: jmp rel32 (direct near jump)
        // - 0xeb: jmp rel8 (short jump)

        let mut i = 0;
        while i < code.len().saturating_sub(6) {
            // Check for indirect jmp (ff /4)
            if code[i] == 0xff {
                let modrm = code[i + 1];
                // ModR/M byte: bits 3-5 = reg/opcode field
                // For jmp, opcode field = 4
                let reg_opcode = (modrm >> 3) & 0x7;

                if reg_opcode == 4 {
                    // Found a JMP instruction!
                    // Determine instruction length based on ModR/M
                    let inst_len = match modrm & 0xC0 {
                        0x00 => {
                            // [reg] or special cases
                            if (modrm & 0x07) == 5 {
                                // jmp [rip+disp32]
                                6
                            } else {
                                2
                            }
                        }
                        0x40 => 3, // [reg+disp8]
                        0x80 => 6, // [reg+disp32]
                        0xC0 => 2, // reg (e.g., jmp rax)
                        _ => 2,
                    };

                    let return_addr = base_addr + (i + inst_len) as u64;
                    debug!(
                        "Found JMP instruction at offset 0x{:x}, instruction: {:02x} {:02x}, return addr: 0x{:x}",
                        i, code[i], code[i + 1], return_addr
                    );
                    return Ok(return_addr);
                }
            }
            // Check for direct near jump (e9 rel32)
            else if code[i] == 0xe9 {
                let return_addr = base_addr + (i + 5) as u64;
                debug!(
                    "Found JMP rel32 at offset 0x{:x}, return addr: 0x{:x}",
                    i, return_addr
                );
                return Ok(return_addr);
            }
            // Check for short jump (eb rel8) - less likely but possible
            else if code[i] == 0xeb {
                let return_addr = base_addr + (i + 2) as u64;
                debug!(
                    "Found JMP rel8 at offset 0x{:x}, return addr: 0x{:x}",
                    i, return_addr
                );
                return Ok(return_addr);
            }

            i += 1;
        }

        warn!("No JMP instruction found in execute_ex code");
        Ok(0)
    }

    /// Extract JIT return address from aarch64 execute_ex
    ///
    /// Find the first BR (branch register)
    /// instruction in execute_ex. This is an unconditional jump through a register,
    /// which is how PHP JIT code is called using GCC's "labels as values" feature.
    ///
    /// Example assembly:
    ///   xxx - 4: ...
    ///   xxx    : br x0
    ///   xxx + 4: ...     <---- This is the return address we care about.
    fn extract_jit_return_address_aarch64(&self, code: &[u8], base_addr: u64) -> Result<u64> {
        // Scan through the code looking for BR (branch register) instructions
        // ARM64 instructions are always 4 bytes aligned

        for i in (0..code.len().saturating_sub(4)).step_by(4) {
            let instr = u32::from_le_bytes([code[i], code[i + 1], code[i + 2], code[i + 3]]);

            // Check for BR instruction
            // Format: 1101 0110 0001 1111 0000 00nn nnn0 0000
            // Opcode: 0xd61f0000
            // Mask:   0xfffffc1f (ignore bits for register selection)
            if (instr & 0xfffffc1f) == 0xd61f0000 {
                // Found BR instruction!
                // Extract the register number (bits 5-9)
                let reg = (instr >> 5) & 0x1f;

                // Return address is the next instruction (4 bytes after)
                if i + 4 < code.len() {
                    let return_addr = base_addr + (i + 4) as u64;
                    debug!(
                        "Found BR x{} at offset 0x{:x}, return addr: 0x{:x}",
                        reg, i, return_addr
                    );
                    return Ok(return_addr);
                }
            }
        }

        warn!("No BR instruction found in execute_ex code");
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
mod tests;
