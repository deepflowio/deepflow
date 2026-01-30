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

//! Thread Pointer Base (TPBASE) offset extraction
//!
//! This module extracts the offset of fsbase/tpidr in task_struct by analyzing
//! kernel functions. This is needed for accessing Thread Local Storage (TLS)
//! from eBPF programs.
//!
//! On x86_64, the thread pointer base is stored in task_struct.thread.fsbase
//! On arm64, it's stored in task_struct.thread.uw.tp_value

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

use log::{debug, trace, warn};

use crate::error::{Error, Result};

// Constants for TPBASE offset validation
/// Minimum reasonable TPBASE offset (task_struct.thread.fsbase should be after basic fields)
const TPBASE_MIN_OFFSET: u32 = 500;
/// Maximum reasonable TPBASE offset (thread struct shouldn't be too deep in task_struct)
const TPBASE_MAX_OFFSET: u32 = 20000;

// Default TPBASE offsets for different architectures
/// Default x86_64 TPBASE offset (common for Ubuntu/Debian kernels 5.x/6.x)
#[cfg(target_arch = "x86_64")]
const DEFAULT_X86_64_TPBASE_OFFSET: u64 = 0x1978; // 6520 bytes
/// Default ARM64 TPBASE offset (placeholder, needs verification)
#[cfg(target_arch = "aarch64")]
const DEFAULT_AARCH64_TPBASE_OFFSET: u64 = 0x1000;

/// Kernel function analyzers for extracting TPBASE offset
struct Analyzer {
    function_name: &'static str,
    analyze: fn(&[u8]) -> Option<u32>,
}

/// Get the list of analyzers for the current architecture
fn get_analyzers() -> Vec<Analyzer> {
    #[cfg(target_arch = "x86_64")]
    {
        vec![
            Analyzer {
                function_name: "x86_fsbase_write_task",
                analyze: analyze_fsbase_write_task_x86,
            },
            Analyzer {
                function_name: "aout_dump_debugregs",
                analyze: analyze_aout_dump_debugregs_x86,
            },
        ]
    }
    #[cfg(target_arch = "aarch64")]
    {
        vec![Analyzer {
            function_name: "tls_thread_switch",
            analyze: analyze_tls_thread_switch_arm64,
        }]
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        vec![]
    }
}

/// Analyze x86_fsbase_write_task function to extract fsbase offset.
///
/// This function simply writes the second argument (fsbase value) to
/// task_struct at the fsbase offset. Available since kernel version 4.20.
///
/// Expected pattern:
///   48 89 b7 XX XX XX XX    mov %rsi, 0xXXXXXXXX(%rdi)
///
/// Where %rdi is task_struct pointer and %rsi is fsbase value
#[cfg(target_arch = "x86_64")]
fn analyze_fsbase_write_task_x86(code: &[u8]) -> Option<u32> {
    // Pattern: REX.W MOV r/m64, r64 with RDI base and RSI source
    // 48 89 b7 = mov %rsi, offset(%rdi)
    let pattern = [0x48, 0x89, 0xb7];

    if let Some(idx) = code.windows(3).position(|w| w == pattern) {
        if idx + 7 <= code.len() {
            let offset =
                u32::from_le_bytes([code[idx + 3], code[idx + 4], code[idx + 5], code[idx + 6]]);
            trace!(
                "Found fsbase offset {:#x} from x86_fsbase_write_task",
                offset
            );
            return Some(offset);
        }
    }
    None
}

/// Analyze aout_dump_debugregs function to extract fsbase offset.
/// This is a fallback for older kernels that don't have x86_fsbase_write_task.
///
/// This function reads task->thread.fsbase, so we look for memory loads
/// from task_struct with a specific pattern.
#[cfg(target_arch = "x86_64")]
fn analyze_aout_dump_debugregs_x86(code: &[u8]) -> Option<u32> {
    // This is more complex - would need full disassembly
    // For simplicity, look for common patterns
    // Pattern: mov XX(%rdi), %rXX or mov XX(%rsi), %rXX

    // Look for 48 8b XX XX XX XX XX patterns (mov r64, m64)
    for i in 0..code.len().saturating_sub(7) {
        // REX.W MOV r64, [rdi + disp32]
        if code[i] == 0x48 && code[i + 1] == 0x8b {
            let modrm = code[i + 2];
            let mod_field = modrm >> 6;
            let rm_field = modrm & 0x7;

            // mod=10 (disp32), rm=111 (rdi)
            if mod_field == 2 && rm_field == 7 {
                let offset =
                    u32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
                // fsbase offset is typically in range TPBASE_MIN_OFFSET-TPBASE_MAX_OFFSET
                // and should be related to thread.fsbase
                // The actual fsbase is at offset-16 from debugreg storage
                if offset > TPBASE_MIN_OFFSET && offset < TPBASE_MAX_OFFSET {
                    // Adjust for the debugreg offset (fsbase is typically 16 bytes before)
                    let fsbase_offset = offset.saturating_sub(16);
                    trace!(
                        "Found potential fsbase offset {:#x} (adjusted from {:#x}) from aout_dump_debugregs",
                        fsbase_offset, offset
                    );
                    return Some(fsbase_offset);
                }
            }
        }
    }
    None
}

/// Analyze tls_thread_switch function on ARM64 to extract tp_value offset.
#[cfg(target_arch = "aarch64")]
fn analyze_tls_thread_switch_arm64(_code: &[u8]) -> Option<u32> {
    // ARM64 pattern analysis would go here
    // For now, return None as this needs more investigation
    None
}

/// Read kernel function code at the given address
fn read_kernel_code(addr: u64, size: usize) -> Result<Vec<u8>> {
    let mut file = File::open("/proc/kcore")?;

    // /proc/kcore is an ELF core dump format
    // We need to parse the ELF headers to find the correct offset
    // For simplicity, try to read from /dev/kmem first if available

    // Try /dev/kmem (may not be available on all systems)
    if let Ok(mut kmem) = File::open("/dev/kmem") {
        kmem.seek(SeekFrom::Start(addr))?;
        let mut buf = vec![0u8; size];
        kmem.read_exact(&mut buf)?;
        return Ok(buf);
    }

    // Fallback: try to use /proc/kcore with ELF parsing
    read_kernel_code_from_kcore(&mut file, addr, size)
}

/// Read kernel code from /proc/kcore (ELF core dump format)
fn read_kernel_code_from_kcore(file: &mut File, addr: u64, size: usize) -> Result<Vec<u8>> {
    use object::{elf, read::elf::FileHeader, Endianness};

    // Read the entire header section first to parse program headers
    file.seek(SeekFrom::Start(0))?;
    let mut header_data = vec![0u8; 4096]; // Should be enough for headers
    file.read_exact(&mut header_data)?;

    // Parse header to get program header info
    let (endian, phoff, phnum, phentsize) = {
        let header = elf::FileHeader64::<Endianness>::parse(&header_data[..])
            .map_err(|e| Error::Msg(format!("Failed to parse kcore ELF header: {}", e)))?;
        let endian = header
            .endian()
            .map_err(|e| Error::Msg(format!("Failed to get endianness: {}", e)))?;
        let phoff = header.e_phoff(endian) as usize;
        let phnum = header.e_phnum(endian) as usize;
        let phentsize = header.e_phentsize(endian) as usize;
        (endian, phoff, phnum, phentsize)
    };

    // Ensure we have enough data
    let needed_size = phoff + phnum * phentsize;
    if needed_size > header_data.len() {
        header_data.resize(needed_size, 0);
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut header_data)?;
    }

    // Re-parse the header with complete data
    let header = elf::FileHeader64::<Endianness>::parse(&header_data[..])
        .map_err(|e| Error::Msg(format!("Failed to parse kcore ELF header: {}", e)))?;

    let program_headers = header
        .program_headers(endian, &header_data[..])
        .map_err(|e| Error::Msg(format!("Failed to parse program headers: {}", e)))?;

    find_and_read_segment(file, program_headers, endian, addr, size)
}

/// Helper function to find and read segment from program headers
fn find_and_read_segment<E: object::endian::Endian>(
    file: &mut File,
    program_headers: &[object::elf::ProgramHeader64<E>],
    endian: E,
    addr: u64,
    size: usize,
) -> Result<Vec<u8>> {
    use object::{elf, read::elf::ProgramHeader};

    // Find the segment containing our address
    for phdr in program_headers {
        if phdr.p_type(endian) != elf::PT_LOAD {
            continue;
        }

        let p_vaddr = phdr.p_vaddr(endian);
        let p_memsz = phdr.p_memsz(endian);
        let p_offset = phdr.p_offset(endian);

        if addr >= p_vaddr && addr < p_vaddr + p_memsz {
            let file_offset = p_offset + (addr - p_vaddr);
            file.seek(SeekFrom::Start(file_offset))?;
            let mut buf = vec![0u8; size];
            file.read_exact(&mut buf)?;
            return Ok(buf);
        }
    }

    Err(Error::Msg(format!(
        "Address {:#x} not found in kcore segments",
        addr
    )))
}

/// Look up a kernel symbol address from /proc/kallsyms
fn lookup_kernel_symbol(name: &str) -> Result<u64> {
    let file = File::open("/proc/kallsyms")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] == name {
            let addr = u64::from_str_radix(parts[0], 16)
                .map_err(|e| Error::Msg(format!("Failed to parse address: {}", e)))?;
            if addr == 0 {
                // kallsyms may show 0 address when kptr_restrict is enabled
                return Err(Error::Msg(
                    "kallsyms shows 0 address, try running as root or set kptr_restrict=0"
                        .to_string(),
                ));
            }
            return Ok(addr);
        }
    }

    Err(Error::Msg(format!("Symbol {} not found in kallsyms", name)))
}

/// Extract TPBASE offset from kernel functions
///
/// This function tries multiple kernel functions to extract the offset
/// of the thread pointer base (fsbase on x86_64, tp_value on arm64)
/// within task_struct.
pub fn extract_tpbase_offset() -> Result<u64> {
    let analyzers = get_analyzers();
    if analyzers.is_empty() {
        return Err(Error::Msg(
            "No TPBASE analyzers for this architecture".to_string(),
        ));
    }

    for analyzer in analyzers {
        match lookup_kernel_symbol(analyzer.function_name) {
            Ok(addr) => {
                trace!(
                    "Found kernel symbol {} at {:#x}",
                    analyzer.function_name,
                    addr
                );

                // Read function code (256 bytes should be enough for analysis)
                match read_kernel_code(addr, 256) {
                    Ok(code) => {
                        if let Some(offset) = (analyzer.analyze)(&code) {
                            // Sanity check: offset should be in reasonable range
                            if offset >= TPBASE_MIN_OFFSET && offset <= TPBASE_MAX_OFFSET {
                                debug!(
                                    "Extracted TPBASE offset {} ({:#x}) from {}",
                                    offset, offset, analyzer.function_name
                                );
                                return Ok(offset as u64);
                            } else {
                                warn!(
                                    "TPBASE offset {} from {} seems invalid (expected {}-{})",
                                    offset,
                                    analyzer.function_name,
                                    TPBASE_MIN_OFFSET,
                                    TPBASE_MAX_OFFSET
                                );
                            }
                        }
                    }
                    Err(e) => {
                        debug!(
                            "Failed to read kernel code for {}: {}",
                            analyzer.function_name, e
                        );
                    }
                }
            }
            Err(e) => {
                trace!("Symbol {} not found: {}", analyzer.function_name, e);
            }
        }
    }

    // If we can't extract from kernel functions, try BTF as fallback
    extract_tpbase_offset_from_btf()
}

/// Extract TPBASE offset from kernel BTF information
fn extract_tpbase_offset_from_btf() -> Result<u64> {
    // Try to use BTF to get the offset of thread.fsbase in task_struct
    // This is a fallback when kernel function analysis fails

    // For x86_64: task_struct.thread.fsbase
    // For arm64: task_struct.thread.uw.tp_value

    #[cfg(target_arch = "x86_64")]
    {
        // Try parsing /sys/kernel/btf/vmlinux
        match parse_btf_for_tpbase() {
            Ok(offset) => {
                debug!(
                    "Extracted TPBASE offset {} ({:#x}) from BTF",
                    offset, offset
                );
                return Ok(offset);
            }
            Err(e) => {
                debug!("BTF parsing failed: {}", e);
            }
        }

        // Fallback to hardcoded defaults based on common kernel configurations
        // These values are extracted from various kernel versions
        get_default_tpbase_offset()
    }

    #[cfg(target_arch = "aarch64")]
    {
        // For ARM64: task_struct.thread.uw.tp_value
        // Default offset for common kernel configurations
        get_default_tpbase_offset()
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(Error::Msg(
            "TPBASE extraction not supported for this architecture".to_string(),
        ))
    }
}

/// Parse BTF information from /sys/kernel/btf/vmlinux to get TPBASE offset
#[cfg(target_arch = "x86_64")]
fn parse_btf_for_tpbase() -> Result<u64> {
    use std::fs::File;
    use std::io::Read;

    // Read BTF data from sysfs
    let btf_path = "/sys/kernel/btf/vmlinux";
    let mut file =
        File::open(btf_path).map_err(|e| Error::Msg(format!("Cannot open {}: {}", btf_path, e)))?;

    let mut btf_data = Vec::new();
    file.read_to_end(&mut btf_data)
        .map_err(|e| Error::Msg(format!("Cannot read {}: {}", btf_path, e)))?;

    // Parse BTF header to find task_struct and thread.fsbase offset
    // BTF format: https://www.kernel.org/doc/html/latest/bpf/btf.html
    parse_btf_task_struct_fsbase(&btf_data)
}

/// Parse BTF data to find task_struct.thread.fsbase offset
#[cfg(target_arch = "x86_64")]
fn parse_btf_task_struct_fsbase(btf_data: &[u8]) -> Result<u64> {
    // BTF header structure (from include/uapi/linux/btf.h)
    // struct btf_header {
    //     __u16 magic;      // 0xEB9F
    //     __u8  version;    // 1
    //     __u8  flags;
    //     __u32 hdr_len;
    //     __u32 type_off;   // offset of type section
    //     __u32 type_len;   // length of type section
    //     __u32 str_off;    // offset of string section
    //     __u32 str_len;    // length of string section
    // };

    if btf_data.len() < 24 {
        return Err(Error::Msg("BTF data too small".to_string()));
    }

    let magic = u16::from_le_bytes([btf_data[0], btf_data[1]]);
    if magic != 0xEB9F {
        return Err(Error::Msg(format!("Invalid BTF magic: {:#x}", magic)));
    }

    let hdr_len = u32::from_le_bytes([btf_data[4], btf_data[5], btf_data[6], btf_data[7]]) as usize;
    let type_off =
        u32::from_le_bytes([btf_data[8], btf_data[9], btf_data[10], btf_data[11]]) as usize;
    let type_len =
        u32::from_le_bytes([btf_data[12], btf_data[13], btf_data[14], btf_data[15]]) as usize;
    let str_off =
        u32::from_le_bytes([btf_data[16], btf_data[17], btf_data[18], btf_data[19]]) as usize;
    let str_len =
        u32::from_le_bytes([btf_data[20], btf_data[21], btf_data[22], btf_data[23]]) as usize;

    let type_section_start = hdr_len + type_off;
    let str_section_start = hdr_len + str_off;

    if type_section_start + type_len > btf_data.len()
        || str_section_start + str_len > btf_data.len()
    {
        return Err(Error::Msg("BTF sections out of bounds".to_string()));
    }

    let type_section = &btf_data[type_section_start..type_section_start + type_len];
    let str_section = &btf_data[str_section_start..str_section_start + str_len];

    // Find task_struct type ID first
    let task_struct_id = find_btf_struct_by_name(type_section, str_section, "task_struct")?;

    // Find thread member in task_struct
    let thread_offset =
        find_btf_member_offset(type_section, str_section, task_struct_id, "thread")?;

    // Find thread_struct type and fsbase offset within it
    let thread_type_id = find_btf_member_type(type_section, str_section, task_struct_id, "thread")?;
    let fsbase_offset =
        find_btf_member_offset(type_section, str_section, thread_type_id, "fsbase")?;

    let total_offset = thread_offset + fsbase_offset;

    // Sanity check
    if total_offset < TPBASE_MIN_OFFSET as u64 || total_offset > TPBASE_MAX_OFFSET as u64 {
        return Err(Error::Msg(format!(
            "BTF offset {} seems invalid (expected {}-{})",
            total_offset, TPBASE_MIN_OFFSET, TPBASE_MAX_OFFSET
        )));
    }

    Ok(total_offset)
}

/// BTF type kinds
#[cfg(target_arch = "x86_64")]
const BTF_KIND_STRUCT: u32 = 4;
#[cfg(target_arch = "x86_64")]
const BTF_KIND_UNION: u32 = 5;

/// Calculate extra size for a BTF type based on its kind and vlen
#[cfg(target_arch = "x86_64")]
fn btf_type_extra_size(kind: u32, vlen: u32) -> usize {
    match kind {
        1 => 4,                        // BTF_KIND_INT
        2 => 0,                        // PTR
        3 => 12,                       // ARRAY
        4 | 5 => (vlen * 12) as usize, // STRUCT, UNION: each member is 12 bytes
        6 => (vlen * 8) as usize,      // ENUM (64-bit: each enumerator is 8 bytes)
        7 => 0,                        // FWD
        8 => 0,                        // TYPEDEF
        9 => 0,                        // VOLATILE
        10 => 0,                       // CONST
        11 => 0,                       // RESTRICT
        12 => 0,                       // FUNC
        13 => (vlen * 8) as usize,     // FUNC_PROTO: each param is 8 bytes
        14 => 12,                      // VAR
        15 => (vlen * 12) as usize,    // DATASEC
        16 => 0,                       // FLOAT
        17 => 4,                       // DECL_TAG
        18 => 0,                       // TYPE_TAG
        19 => (vlen * 8) as usize,     // ENUM64
        _ => 0,
    }
}

/// Find BTF struct type ID by name
#[cfg(target_arch = "x86_64")]
fn find_btf_struct_by_name(type_section: &[u8], str_section: &[u8], name: &str) -> Result<u32> {
    // BTF type format:
    // struct btf_type {
    //     __u32 name_off;
    //     __u32 info;       // kind in bits 24-28
    //     union { __u32 size; __u32 type; };
    // };
    // For struct, followed by btf_member array

    let mut offset = 0;
    let mut type_id = 1u32; // BTF type IDs start at 1

    while offset + 12 <= type_section.len() {
        let name_off = u32::from_le_bytes([
            type_section[offset],
            type_section[offset + 1],
            type_section[offset + 2],
            type_section[offset + 3],
        ]) as usize;

        let info = u32::from_le_bytes([
            type_section[offset + 4],
            type_section[offset + 5],
            type_section[offset + 6],
            type_section[offset + 7],
        ]);

        let kind = (info >> 24) & 0x1f;
        let vlen = info & 0xffff; // number of members for struct

        // Skip the base btf_type (12 bytes)
        let extra_size = btf_type_extra_size(kind, vlen);

        if kind == BTF_KIND_STRUCT {
            // Check if this is the struct we're looking for
            if name_off < str_section.len() {
                let type_name = get_btf_string(str_section, name_off);
                if type_name == name {
                    return Ok(type_id);
                }
            }
        }

        offset += 12 + extra_size; // 12 = type_base_size
        type_id += 1;
    }

    Err(Error::Msg(format!("BTF struct '{}' not found", name)))
}

/// Find offset of a member in a BTF struct
#[cfg(target_arch = "x86_64")]
fn find_btf_member_offset(
    type_section: &[u8],
    str_section: &[u8],
    struct_id: u32,
    member_name: &str,
) -> Result<u64> {
    // Navigate to the struct type entry
    let mut offset = 0;
    let mut current_id = 1u32;

    while offset + 12 <= type_section.len() && current_id <= struct_id {
        let info = u32::from_le_bytes([
            type_section[offset + 4],
            type_section[offset + 5],
            type_section[offset + 6],
            type_section[offset + 7],
        ]);

        let kind = (info >> 24) & 0x1f;
        let vlen = info & 0xffff;

        let extra_size = btf_type_extra_size(kind, vlen);

        if current_id == struct_id && (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) {
            // Found the struct, now search its members
            let members_start = offset + 12; // btf_type base size
            for i in 0..vlen as usize {
                let member_offset = members_start + i * 12;
                if member_offset + 12 > type_section.len() {
                    break;
                }

                let mem_name_off = u32::from_le_bytes([
                    type_section[member_offset],
                    type_section[member_offset + 1],
                    type_section[member_offset + 2],
                    type_section[member_offset + 3],
                ]) as usize;

                let mem_offset_bits = u32::from_le_bytes([
                    type_section[member_offset + 8],
                    type_section[member_offset + 9],
                    type_section[member_offset + 10],
                    type_section[member_offset + 11],
                ]);

                if mem_name_off < str_section.len() {
                    let mem_name = get_btf_string(str_section, mem_name_off);
                    if mem_name == member_name {
                        // Convert bits to bytes (normal struct members are byte-aligned)
                        return Ok((mem_offset_bits / 8) as u64);
                    }
                }
            }
            return Err(Error::Msg(format!(
                "Member '{}' not found in struct",
                member_name
            )));
        }

        offset += 12 + extra_size; // 12 = btf_type base size
        current_id += 1;
    }

    Err(Error::Msg(format!("Struct ID {} not found", struct_id)))
}

/// Find type ID of a member in a BTF struct
#[cfg(target_arch = "x86_64")]
fn find_btf_member_type(
    type_section: &[u8],
    str_section: &[u8],
    struct_id: u32,
    member_name: &str,
) -> Result<u32> {
    let mut offset = 0;
    let mut current_id = 1u32;

    while offset + 12 <= type_section.len() && current_id <= struct_id {
        let info = u32::from_le_bytes([
            type_section[offset + 4],
            type_section[offset + 5],
            type_section[offset + 6],
            type_section[offset + 7],
        ]);

        let kind = (info >> 24) & 0x1f;
        let vlen = info & 0xffff;

        let extra_size = btf_type_extra_size(kind, vlen);

        if current_id == struct_id && (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) {
            let members_start = offset + 12; // btf_type base size
            for i in 0..vlen as usize {
                let member_offset = members_start + i * 12;
                if member_offset + 12 > type_section.len() {
                    break;
                }

                let mem_name_off = u32::from_le_bytes([
                    type_section[member_offset],
                    type_section[member_offset + 1],
                    type_section[member_offset + 2],
                    type_section[member_offset + 3],
                ]) as usize;

                let mem_type = u32::from_le_bytes([
                    type_section[member_offset + 4],
                    type_section[member_offset + 5],
                    type_section[member_offset + 6],
                    type_section[member_offset + 7],
                ]);

                if mem_name_off < str_section.len() {
                    let mem_name = get_btf_string(str_section, mem_name_off);
                    if mem_name == member_name {
                        return Ok(mem_type);
                    }
                }
            }
            return Err(Error::Msg(format!(
                "Member '{}' not found in struct",
                member_name
            )));
        }

        offset += 12 + extra_size; // 12 = btf_type base size
        current_id += 1;
    }

    Err(Error::Msg(format!("Struct ID {} not found", struct_id)))
}

/// Get null-terminated string from BTF string section
#[cfg(target_arch = "x86_64")]
fn get_btf_string(str_section: &[u8], offset: usize) -> &str {
    if offset >= str_section.len() {
        return "";
    }
    let bytes = &str_section[offset..];
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).unwrap_or("")
}

/// Get default TPBASE offset based on common kernel configurations
///
/// These values are derived from analysis of various kernel versions.
/// The offset of task_struct.thread.fsbase varies based on kernel configuration
/// but typically falls within a predictable range.
fn get_default_tpbase_offset() -> Result<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        // Common offsets for x86_64 kernels:
        // - kernel 5.x: typically around 0x1940-0x1A00 (6464-6656)
        // - kernel 6.x: typically around 0x1940-0x1A80 (6464-6784)
        //
        // The exact offset depends on CONFIG_* options, especially:
        // - CONFIG_KASAN
        // - CONFIG_MEMCG
        // - CONFIG_CGROUPS
        // - CONFIG_BPF_SYSCALL
        //
        // We use a common value that works for most distributions
        let default_offset = DEFAULT_X86_64_TPBASE_OFFSET;

        warn!(
            "Using default TPBASE offset {:#x} ({}). This may not be accurate for all kernels.",
            default_offset, default_offset
        );
        Ok(default_offset)
    }

    #[cfg(target_arch = "aarch64")]
    {
        // For ARM64: task_struct.thread.uw.tp_value
        // Common offset for arm64 kernels
        let default_offset = DEFAULT_AARCH64_TPBASE_OFFSET;

        warn!(
            "Using default TPBASE offset {:#x} for arm64. This may not be accurate.",
            default_offset
        );
        Ok(default_offset)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(Error::Msg(
            "Default TPBASE offset not available for this architecture".to_string(),
        ))
    }
}

/// C-callable function to read TPBASE offset
#[no_mangle]
pub extern "C" fn read_tpbase_offset() -> i64 {
    match extract_tpbase_offset() {
        Ok(offset) => offset as i64,
        Err(e) => {
            warn!("Failed to extract TPBASE offset: {}", e);
            // Return default offset instead of -1 to allow Python profiling to work
            #[cfg(target_arch = "x86_64")]
            {
                let default = DEFAULT_X86_64_TPBASE_OFFSET as i64;
                warn!("Using fallback TPBASE offset: {:#x}", default);
                return default;
            }
            #[cfg(target_arch = "aarch64")]
            {
                let default = DEFAULT_AARCH64_TPBASE_OFFSET as i64;
                warn!("Using fallback TPBASE offset: {:#x}", default);
                return default;
            }
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                -1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_fsbase_write_task_x86() {
        // Test pattern: mov %rsi, 0x1234(%rdi)
        // 48 89 b7 34 12 00 00
        let code = [0x48, 0x89, 0xb7, 0x34, 0x12, 0x00, 0x00];
        let result = analyze_fsbase_write_task_x86(&code);
        assert_eq!(result, Some(0x1234));
    }

    #[test]
    fn test_analyze_fsbase_write_task_x86_with_prefix() {
        // Test with some prefix instructions
        let code = [
            0x55, // push rbp
            0x48, 0x89, 0xe5, // mov rbp, rsp
            0x48, 0x89, 0xb7, 0x78, 0x19, 0x00, 0x00, // mov %rsi, 0x1978(%rdi)
            0x5d, // pop rbp
            0xc3, // ret
        ];
        let result = analyze_fsbase_write_task_x86(&code);
        assert_eq!(result, Some(0x1978));
    }
}
