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

//! Thread Specific Data (TSD) extraction module
//!
//! This module analyzes the C library's pthread_getspecific function to extract
//! the parameters needed to access thread-specific data from eBPF.
//!
//! The TSD info includes:
//! - offset: Offset from thread pointer base to TSD storage
//! - multiplier: Size of each TSD entry (8 for musl, 16 for glibc)
//! - indirect: Whether indirect addressing is needed (1 for musl, 0 for glibc)
//!
//! C library implementations:
//! - musl: pthread->tsd[key] (indirect, multiplier=8)
//! - glibc: pthread->specific_1stblock[key].data (direct, multiplier=16)

use std::cell::OnceCell;
use std::fs;
use std::path::PathBuf;

use ahash::AHashMap;
use log::trace;
use object::{Object, ObjectSection, ObjectSymbol};
use regex::Regex;

use crate::error::{Error, Result};
use crate::maps::{get_memory_mappings, MemoryArea};

use super::python::TSDInfo;

#[cfg(target_arch = "x86_64")]
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

// TSD constants for different C library implementations
/// glibc: each TSD entry is struct pthread_key_data { uintptr_t seq; void *data; } = 16 bytes
const GLIBC_TSD_MULTIPLIER: u8 = 16;
/// musl: each TSD entry is a pointer = 8 bytes
const MUSL_TSD_MULTIPLIER: u8 = 8;

/// glibc: TSD is inline in pthread struct (no indirection)
const GLIBC_TSD_INDIRECT: u8 = 0;
/// musl: pthread->tsd is a pointer that needs dereferencing
const MUSL_TSD_INDIRECT: u8 = 1;

/// Default glibc TSD offset (pthread->specific_1stblock + 8, for data field)
const GLIBC_TSD_DEFAULT_OFFSET: i16 = 0x318;
/// Default musl TSD offset (pthread->tsd)
const MUSL_TSD_DEFAULT_OFFSET: i16 = 128;

thread_local! {
    static LIBC_REGEX: OnceCell<Regex> = OnceCell::new();
}

/// Check if a DSO path potentially contains pthread code
pub fn is_potential_tsd_dso(path: &str) -> bool {
    LIBC_REGEX.with(|r| {
        r.get_or_init(|| Regex::new(r".*/(ld-musl|libc|libpthread)([-.].*)?\.so").unwrap())
            .is_match(path)
    })
}

/// Find the libc DSO for a given process
fn find_libc_dso(pid: u32) -> Result<MemoryArea> {
    let mm = get_memory_mappings(pid)?;

    // Priority: libc.so.6 > libpthread.so.0 > ld-musl-*.so.1
    // Note: Modern glibc (2.34+) has pthread implementation in libc.so.6,
    // so we prefer libc.so.6 over libpthread.so.0
    let candidates: Vec<&MemoryArea> = mm
        .iter()
        .filter(|m| is_potential_tsd_dso(&m.path))
        .collect();

    if candidates.is_empty() {
        return Err(Error::Msg(format!(
            "No libc/pthread DSO found for process {}",
            pid
        )));
    }

    // Prefer libc.so.6 for modern glibc (pthread is now in libc)
    for c in &candidates {
        if c.path.contains("libc.so") {
            return Ok((*c).clone());
        }
    }
    // Fallback to libpthread.so.0 for older glibc
    for c in &candidates {
        if c.path.contains("libpthread") {
            return Ok((*c).clone());
        }
    }
    // musl libc variants
    for c in &candidates {
        if c.path.contains("libc.musl") || c.path.contains("ld-musl") {
            return Ok((*c).clone());
        }
    }

    Ok(candidates[0].clone())
}

/// Read pthread_getspecific function code from a DSO
fn read_pthread_getspecific_code(pid: u32, dso: &MemoryArea) -> Result<Vec<u8>> {
    // Try reading from the file system first (works for host processes)
    if let Ok(code) = read_pthread_getspecific_from_file(pid, dso) {
        return Ok(code);
    }

    // Fallback: read from process memory (works for container processes)
    read_pthread_getspecific_from_memory(pid, dso)
}

/// Read pthread_getspecific function code from file system
fn read_pthread_getspecific_from_file(pid: u32, dso: &MemoryArea) -> Result<Vec<u8>> {
    let base: PathBuf = ["/proc", &pid.to_string(), "root"].iter().collect();
    let path = base.join(&dso.path[1..]);

    let data = fs::read(&path)
        .map_err(|e| Error::Msg(format!("Cannot read DSO file {}: {}", path.display(), e)))?;
    let obj = object::File::parse(&*data)?;

    read_symbol_code_from_elf(&obj, dso)
}

/// Read pthread_getspecific function code from process memory
fn read_pthread_getspecific_from_memory(pid: u32, dso: &MemoryArea) -> Result<Vec<u8>> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    // First, get symbol offset from the DSO file (try multiple paths)
    let symbol_offset = get_pthread_getspecific_offset(pid, dso)?;

    // Calculate actual memory address
    let mem_addr = dso.m_start + symbol_offset;

    // Read from /proc/{pid}/mem
    let mem_path = format!("/proc/{}/mem", pid);
    let mut mem_file = File::open(&mem_path)
        .map_err(|e| Error::Msg(format!("Cannot open {}: {}", mem_path, e)))?;

    mem_file
        .seek(SeekFrom::Start(mem_addr))
        .map_err(|e| Error::Msg(format!("Cannot seek in {}: {}", mem_path, e)))?;

    let mut code = vec![0u8; 256];
    mem_file
        .read_exact(&mut code)
        .map_err(|e| Error::Msg(format!("Cannot read from {}: {}", mem_path, e)))?;

    trace!(
        "Read pthread_getspecific from process memory at {:#x}",
        mem_addr
    );

    Ok(code)
}

/// Get the offset of pthread_getspecific within the DSO
fn get_pthread_getspecific_offset(pid: u32, dso: &MemoryArea) -> Result<u64> {
    // Handle " (deleted)" suffix which may be present in memory mappings
    let clean_path_str = if let Some(stripped) = dso.path.strip_suffix(" (deleted)") {
        stripped
    } else {
        &dso.path
    };

    // 1. Try /proc/{pid}/root/{path}
    let base: PathBuf = ["/proc", &pid.to_string(), "root"].iter().collect();
    // dso.path usually starts with /
    let relative_path = if clean_path_str.starts_with('/') {
        &clean_path_str[1..]
    } else {
        clean_path_str
    };
    let path1 = base.join(relative_path);

    if let Ok(data) = fs::read(&path1) {
        if let Ok(obj) = object::File::parse(&*data) {
            if let Some(offset) = find_pthread_getspecific_offset(&obj) {
                return Ok(offset);
            }
        }
    }

    // 2. Try the path directly (for container overlay fs)
    if let Ok(data) = fs::read(clean_path_str) {
        if let Ok(obj) = object::File::parse(&*data) {
            if let Some(offset) = find_pthread_getspecific_offset(&obj) {
                return Ok(offset);
            }
        }
    }

    // Note: Do not fallback to host libc paths here.
    // If we are in a container, the host libc likely has different offsets.
    // Reading incorrect offsets causes us to read garbage from process memory,
    // leading to failures in extract_tsd_info.

    Err(Error::Msg(format!(
        "Cannot find pthread_getspecific offset in DSO: {}",
        dso.path
    )))
}

/// Find pthread_getspecific symbol offset in an ELF file
fn find_pthread_getspecific_offset(obj: &object::File) -> Option<u64> {
    let symbol_names = ["__pthread_getspecific", "pthread_getspecific"];

    for name in symbol_names {
        if let Some(sym) = obj
            .symbols()
            .chain(obj.dynamic_symbols())
            .find(|s| s.name().map(|n| n == name).unwrap_or(false))
        {
            return Some(sym.address());
        }
    }
    None
}

/// Read symbol code from an ELF file object
fn read_symbol_code_from_elf(obj: &object::File, _dso: &MemoryArea) -> Result<Vec<u8>> {
    // Try both glibc and musl symbol names
    let symbol_names = ["__pthread_getspecific", "pthread_getspecific"];

    for name in symbol_names {
        if let Some(sym) = obj
            .symbols()
            .chain(obj.dynamic_symbols())
            .find(|s| s.name().map(|n| n == name).unwrap_or(false))
        {
            let addr = sym.address();
            let size = sym.size().max(256) as usize; // Read at least 256 bytes

            // Read code from the DSO file
            if let Some(section) = obj.sections().find(|s| {
                let (_start, len) = s.file_range().unwrap_or((0, 0));
                addr >= s.address() && addr < s.address() + len
            }) {
                let section_data = section.data()?;
                let offset = (addr - section.address()) as usize;
                let end = (offset + size).min(section_data.len());

                trace!(
                    "Found {} at {:#x}, reading {} bytes",
                    name,
                    addr,
                    end - offset
                );
                return Ok(section_data[offset..end].to_vec());
            }
        }
    }

    Err(Error::Msg(
        "pthread_getspecific symbol not found in DSO".to_string(),
    ))
}

/// Extract TSD info from pthread_getspecific code (x86_64)
#[cfg(target_arch = "x86_64")]
fn extract_tsd_info_x86(code: &[u8]) -> Result<TSDInfo> {
    if let Some(info) = decode_tsd_info_with_disasm(code) {
        return Ok(info);
    }
    legacy_extract_tsd_info_x86(code)
}

/// Legacy pattern-based extractor kept as a fallback for unknown sequences.
#[cfg(target_arch = "x86_64")]
fn legacy_extract_tsd_info_x86(code: &[u8]) -> Result<TSDInfo> {
    // musl pattern (indirect):
    //   mov %fs:0x0, %rax       ; get pthread struct pointer
    //   mov offset(%rax), %rax  ; load tsd pointer (indirect)
    //   mov (%rax,%rdi,8), %rax ; return tsd[key]

    // Check for musl pattern first
    let musl_fs_pattern = [0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00];
    if code.starts_with(&musl_fs_pattern) {
        for i in 9..code.len().saturating_sub(6) {
            if code[i] == 0x48 && code[i + 1] == 0x8b && code[i + 2] == 0x80 {
                let offset =
                    i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
                trace!("Found musl TSD pattern: offset={}", offset);
                return Ok(TSDInfo {
                    offset: offset as i16,
                    multiplier: MUSL_TSD_MULTIPLIER,
                    indirect: MUSL_TSD_INDIRECT,
                });
            }
        }
    }

    // Check for glibc pattern (fs:0x10)
    let glibc_fs_pattern = [0x64, 0x48, 0x8b, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00];
    if code.starts_with(&glibc_fs_pattern) || code.windows(9).any(|w| w == glibc_fs_pattern) {
        // Strategy 1: Look for SIB addressing (older glibc)
        // mov offset(%rax,%rdi,8), %rax
        for i in 0..code.len().saturating_sub(8) {
            if code[i] == 0x48 && code[i + 1] == 0x8b && code[i + 2] == 0x84 {
                let sib = code[i + 3];
                let scale = 1 << (sib >> 6);
                let offset =
                    i32::from_le_bytes([code[i + 4], code[i + 5], code[i + 6], code[i + 7]]);

                if scale == 8 || scale == 16 {
                    trace!(
                        "Found glibc SIB pattern: offset={}, scale={}",
                        offset,
                        scale
                    );
                    return Ok(TSDInfo {
                        offset: (offset + 8) as i16,
                        multiplier: GLIBC_TSD_MULTIPLIER,
                        indirect: GLIBC_TSD_INDIRECT,
                    });
                }
            }
        }

        // Strategy 2: Look for split instruction pattern (modern glibc)
        // 1. mov %fs:0x10, %rax
        // 2. ... (shl/add instructions)
        // 3. mov offset(%rax), %rax
        for i in 0..code.len().saturating_sub(7) {
            // mov offset(%rax), %rax -> 48 8b 80 XX XX XX XX
            if code[i] == 0x48 && code[i + 1] == 0x8b && code[i + 2] == 0x80 {
                let offset =
                    i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);

                // Heuristic check for reasonable TSD offset
                if offset > 0x100 && offset < 0x2000 {
                    trace!("Found glibc split pattern: offset={}", offset);
                    return Ok(TSDInfo {
                        offset: offset as i16,
                        multiplier: GLIBC_TSD_MULTIPLIER,
                        indirect: GLIBC_TSD_INDIRECT,
                    });
                }
            }
        }
    }

    Err(Error::Msg(format!(
        "Could not extract TSD info from x86_64 code (len={}). Dump: {:02x?}",
        code.len(),
        code
    )))
}

/// Extract TSD info from pthread_getspecific code (ARM64)
#[cfg(target_arch = "aarch64")]
fn extract_tsd_info_arm64(_code: &[u8]) -> Result<TSDInfo> {
    // TODO: Implement ARM64 TSD extraction
    // For now, use default musl-like parameters
    Ok(TSDInfo {
        offset: 0,
        multiplier: MUSL_TSD_MULTIPLIER,
        indirect: MUSL_TSD_INDIRECT,
    })
}

/// Extract TSD info for a given process
pub fn extract_tsd_info(pid: u32) -> Result<TSDInfo> {
    let dso = find_libc_dso(pid)?;
    trace!("Found libc DSO for process {}: {}", pid, dso.path);

    let code = read_pthread_getspecific_code(pid, &dso)?;
    trace!("Read {} bytes of pthread_getspecific code", code.len());

    #[cfg(target_arch = "x86_64")]
    {
        extract_tsd_info_x86(&code)
    }

    #[cfg(target_arch = "aarch64")]
    {
        extract_tsd_info_arm64(&code)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(Error::Msg(
            "TSD extraction not supported on this architecture".to_string(),
        ))
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug)]
enum Expr {
    Unknown,
    Const(i64),
    Key,
    Fs(u64),
    Add(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, i64),
    Deref(Box<Expr>),
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug)]
enum BaseComponent {
    Fs(u64),
    FsDeref { disp: u64, offset: i64 },
}

#[cfg(target_arch = "x86_64")]
fn decode_tsd_info_with_disasm(code: &[u8]) -> Option<TSDInfo> {
    let decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
    let mut regs = vec![
        (Register::RAX, Expr::Unknown),
        (Register::RBX, Expr::Unknown),
        (Register::RCX, Expr::Unknown),
        (Register::RDX, Expr::Unknown),
        (Register::RSI, Expr::Unknown),
        (Register::RDI, Expr::Key),
    ]
    .into_iter()
    .collect::<AHashMap<_, _>>();

    let mut result_expr = None;
    for instr in decoder {
        match instr.mnemonic() {
            Mnemonic::Mov => handle_mov(&instr, &mut regs),
            Mnemonic::Lea => handle_lea(&instr, &mut regs),
            Mnemonic::Add => handle_add(&instr, &mut regs),
            Mnemonic::Shl => handle_shl(&instr, &mut regs),
            Mnemonic::Imul => handle_imul(&instr, &mut regs),
            Mnemonic::Ret => {
                result_expr = regs.get(&Register::RAX).cloned();
                break;
            }
            _ => {}
        }
    }

    let Some(expr) = result_expr else {
        return None;
    };
    match_tsd_expr(&expr)
}

#[cfg(target_arch = "x86_64")]
fn match_tsd_expr(expr: &Expr) -> Option<TSDInfo> {
    match_glibc(expr).or_else(|| match_musl(expr))
}

#[cfg(target_arch = "x86_64")]
fn match_glibc(expr: &Expr) -> Option<TSDInfo> {
    let Expr::Deref(inner) = expr else {
        return None;
    };
    let (base, key_coeff, offset) = linear_components(inner)?;
    let (fs_disp, base_offset) = match base {
        BaseComponent::Fs(fs_disp) => (fs_disp, 0),
        BaseComponent::FsDeref { disp, offset } => (disp, offset),
    };
    if key_coeff == 0 || fs_disp != 0x10 {
        return None;
    }
    let total_offset = offset + base_offset;
    if total_offset < i16::MIN as i64 || total_offset > i16::MAX as i64 {
        return None;
    }
    Some(TSDInfo {
        offset: total_offset as i16,
        multiplier: key_coeff as u8,
        indirect: GLIBC_TSD_INDIRECT,
    })
}

#[cfg(target_arch = "x86_64")]
fn match_musl(expr: &Expr) -> Option<TSDInfo> {
    let Expr::Deref(inner) = expr else {
        return None;
    };
    let mut parts = Vec::new();
    flatten_add(inner, &mut parts);

    let mut base = None;
    let mut key_coeff = 0i64;
    let mut offset = 0i64;

    for part in parts {
        match part {
            Expr::Deref(addr) => {
                if let Some((base_comp, 0, extra)) = linear_components(addr) {
                    match base_comp {
                        BaseComponent::Fs(disp) if disp == 0 => base = Some(extra),
                        BaseComponent::FsDeref { disp, offset: off } if disp == 0 => {
                            base = Some(off + extra)
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                if let Some((None, kc, off)) = linear_components_optional_base(part) {
                    key_coeff += kc;
                    offset += off;
                }
            }
        }
    }

    let Some(base_off) = base else {
        return None;
    };
    if key_coeff == 0 {
        return None;
    }
    let total_offset = base_off + offset;
    if total_offset < i16::MIN as i64 || total_offset > i16::MAX as i64 {
        return None;
    }
    Some(TSDInfo {
        offset: total_offset as i16,
        multiplier: key_coeff as u8,
        indirect: MUSL_TSD_INDIRECT,
    })
}

#[cfg(target_arch = "x86_64")]
fn flatten_add<'a>(expr: &'a Expr, parts: &mut Vec<&'a Expr>) {
    match expr {
        Expr::Add(a, b) => {
            flatten_add(a, parts);
            flatten_add(b, parts);
        }
        _ => parts.push(expr),
    }
}

#[cfg(target_arch = "x86_64")]
fn linear_components(expr: &Expr) -> Option<(BaseComponent, i64, i64)> {
    let (base_opt, key, offset) = linear_components_optional_base(expr)?;
    let base = base_opt?;
    Some((base, key, offset))
}

#[cfg(target_arch = "x86_64")]
fn linear_components_optional_base(expr: &Expr) -> Option<(Option<BaseComponent>, i64, i64)> {
    let mut base = None;
    let mut key_coeff = 0i64;
    let mut offset = 0i64;

    fn walk(
        expr: &Expr,
        base: &mut Option<BaseComponent>,
        key_coeff: &mut i64,
        offset: &mut i64,
    ) -> bool {
        match expr {
            Expr::Add(a, b) => walk(a, base, key_coeff, offset) && walk(b, base, key_coeff, offset),
            Expr::Const(c) => {
                *offset += *c;
                true
            }
            Expr::Key => {
                *key_coeff += 1;
                true
            }
            Expr::Mul(inner, factor) => {
                let mut inner_base = None;
                let mut inner_key = 0;
                let mut inner_off = 0;
                if !walk(inner, &mut inner_base, &mut inner_key, &mut inner_off) {
                    return false;
                }
                if inner_base.is_some() {
                    // Do not try to scale base pointer; treat as unsupported
                    return false;
                }
                *key_coeff += inner_key * *factor;
                *offset += inner_off * *factor;
                true
            }
            Expr::Fs(disp) => {
                if base.is_some() {
                    return false;
                }
                *base = Some(BaseComponent::Fs(*disp));
                true
            }
            Expr::Deref(inner) => {
                // Allow one level of deref for musl base
                let (inner_base, inner_key, inner_off) =
                    match linear_components_optional_base(inner) {
                        Some(v) => v,
                        None => return false,
                    };
                if inner_key != 0 || inner_base.is_none() {
                    return false;
                }
                if base.is_some() {
                    return false;
                }
                let Some(BaseComponent::Fs(disp)) = inner_base else {
                    return false;
                };
                *base = Some(BaseComponent::FsDeref {
                    disp,
                    offset: inner_off,
                });
                true
            }
            Expr::Unknown => true,
        }
    }

    if walk(expr, &mut base, &mut key_coeff, &mut offset) {
        Some((base, key_coeff, offset))
    } else {
        None
    }
}

#[cfg(target_arch = "x86_64")]
fn handle_mov(instr: &Instruction, regs: &mut AHashMap<Register, Expr>) {
    if instr.op0_kind() != OpKind::Register {
        return;
    }
    let dst = canonical_reg(instr.op0_register());
    let new_expr = match instr.op1_kind() {
        OpKind::Register => regs
            .get(&canonical_reg(instr.op1_register()))
            .cloned()
            .unwrap_or(Expr::Unknown),
        OpKind::Immediate64 => Expr::Const(instr.immediate64() as i64),
        OpKind::Immediate32 => Expr::Const(instr.immediate32() as i64),
        OpKind::Memory => Expr::Deref(Box::new(build_address_expr(instr, regs))),
        _ => Expr::Unknown,
    };
    regs.insert(dst, new_expr);
}

#[cfg(target_arch = "x86_64")]
fn handle_lea(instr: &Instruction, regs: &mut AHashMap<Register, Expr>) {
    if instr.op0_kind() != OpKind::Register || instr.op1_kind() != OpKind::Memory {
        return;
    }
    let dst = canonical_reg(instr.op0_register());
    let expr = build_address_expr(instr, regs);
    regs.insert(dst, expr);
}

#[cfg(target_arch = "x86_64")]
fn handle_add(instr: &Instruction, regs: &mut AHashMap<Register, Expr>) {
    if instr.op0_kind() != OpKind::Register {
        return;
    }
    let dst = canonical_reg(instr.op0_register());
    let left = regs.get(&dst).cloned().unwrap_or(Expr::Unknown);
    let right = match instr.op1_kind() {
        OpKind::Immediate32 => Expr::Const(instr.immediate32() as i64),
        OpKind::Immediate8 => Expr::Const(instr.immediate8() as i64),
        OpKind::Register => regs
            .get(&canonical_reg(instr.op1_register()))
            .cloned()
            .unwrap_or(Expr::Unknown),
        OpKind::Memory => Expr::Deref(Box::new(build_address_expr(instr, regs))),
        _ => Expr::Unknown,
    };
    regs.insert(dst, Expr::Add(Box::new(left), Box::new(right)));
}

#[cfg(target_arch = "x86_64")]
fn handle_shl(instr: &Instruction, regs: &mut AHashMap<Register, Expr>) {
    if instr.op0_kind() != OpKind::Register || instr.op1_kind() != OpKind::Immediate8 {
        return;
    }
    let dst = canonical_reg(instr.op0_register());
    let shift = instr.immediate8();
    if shift >= 63 {
        return;
    }
    let factor = 1i64 << shift;
    let expr = regs.get(&dst).cloned().unwrap_or(Expr::Unknown);
    regs.insert(dst, Expr::Mul(Box::new(expr), factor));
}

#[cfg(target_arch = "x86_64")]
fn handle_imul(instr: &Instruction, regs: &mut AHashMap<Register, Expr>) {
    // Only handle the form: imul reg, reg, imm8/imm32
    if instr.op_count() != 3 {
        return;
    }
    if instr.op0_kind() != OpKind::Register || instr.op1_kind() != OpKind::Register {
        return;
    }
    let dst = canonical_reg(instr.op0_register());
    let src = canonical_reg(instr.op1_register());
    if dst != src {
        return;
    }
    let factor = match instr.op2_kind() {
        OpKind::Immediate8 => instr.immediate8() as i64,
        OpKind::Immediate32 => instr.immediate32() as i64,
        _ => return,
    };
    let expr = regs.get(&dst).cloned().unwrap_or(Expr::Unknown);
    regs.insert(dst, Expr::Mul(Box::new(expr), factor));
}

#[cfg(target_arch = "x86_64")]
fn canonical_reg(reg: Register) -> Register {
    match reg {
        Register::RAX | Register::EAX | Register::AX | Register::AL => Register::RAX,
        Register::RBX | Register::EBX | Register::BX | Register::BL => Register::RBX,
        Register::RCX | Register::ECX | Register::CX | Register::CL => Register::RCX,
        Register::RDX | Register::EDX | Register::DX | Register::DL => Register::RDX,
        Register::RSI | Register::ESI | Register::SI | Register::SIL => Register::RSI,
        Register::RDI | Register::EDI | Register::DI | Register::DIL => Register::RDI,
        Register::R8 | Register::R8D | Register::R8W | Register::R8L => Register::R8,
        Register::R9 | Register::R9D | Register::R9W | Register::R9L => Register::R9,
        Register::R10 | Register::R10D | Register::R10W | Register::R10L => Register::R10,
        Register::R11 | Register::R11D | Register::R11W | Register::R11L => Register::R11,
        Register::R12 | Register::R12D | Register::R12W | Register::R12L => Register::R12,
        Register::R13 | Register::R13D | Register::R13W | Register::R13L => Register::R13,
        Register::R14 | Register::R14D | Register::R14W | Register::R14L => Register::R14,
        Register::R15 | Register::R15D | Register::R15W | Register::R15L => Register::R15,
        _ => reg,
    }
}

#[cfg(target_arch = "x86_64")]
fn build_address_expr(instr: &Instruction, regs: &AHashMap<Register, Expr>) -> Expr {
    let mut expr =
        if instr.segment_prefix() == Register::FS && instr.memory_base() == Register::None {
            Expr::Fs(instr.memory_displacement64())
        } else {
            Expr::Const(instr.memory_displacement64() as i64)
        };

    // Base register
    if instr.memory_base() != Register::None {
        let base = canonical_reg(instr.memory_base());
        let base_expr = regs.get(&base).cloned().unwrap_or(Expr::Unknown);
        expr = Expr::Add(Box::new(expr), Box::new(base_expr));
    } else if instr.segment_prefix() == Register::FS && instr.memory_base() == Register::None {
        // already handled
    }

    // RIP-relative
    if instr.memory_base() == Register::RIP {
        expr = Expr::Const(instr.next_ip().wrapping_add(instr.memory_displacement64()) as i64);
    }

    // Index register
    if instr.memory_index() != Register::None {
        let idx = canonical_reg(instr.memory_index());
        let idx_expr = regs.get(&idx).cloned().unwrap_or(Expr::Unknown);
        let scale = instr.memory_index_scale() as i64;
        expr = Expr::Add(
            Box::new(expr),
            Box::new(Expr::Mul(Box::new(idx_expr), scale)),
        );
    }

    expr
}

/// Get default TSD info based on detected libc type
pub fn get_default_tsd_info(pid: u32) -> TSDInfo {
    // Try to detect libc type from memory mappings
    if let Ok(mm) = get_memory_mappings(pid) {
        for m in &mm {
            if m.path.contains("musl") || m.path.contains("ld-musl") {
                // musl libc
                return TSDInfo {
                    offset: MUSL_TSD_DEFAULT_OFFSET,
                    multiplier: MUSL_TSD_MULTIPLIER,
                    indirect: MUSL_TSD_INDIRECT,
                };
            }
            if m.path.contains("libc.so.6") || m.path.contains("libpthread.so.0") {
                // glibc
                return TSDInfo {
                    offset: GLIBC_TSD_DEFAULT_OFFSET,
                    multiplier: GLIBC_TSD_MULTIPLIER,
                    indirect: GLIBC_TSD_INDIRECT,
                };
            }
        }
    }

    // Default to glibc-like parameters (most common)
    TSDInfo {
        offset: GLIBC_TSD_DEFAULT_OFFSET,
        multiplier: GLIBC_TSD_MULTIPLIER,
        indirect: GLIBC_TSD_INDIRECT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_potential_tsd_dso() {
        assert!(is_potential_tsd_dso("/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(is_potential_tsd_dso(
            "/lib/x86_64-linux-gnu/libpthread.so.0"
        ));
        assert!(is_potential_tsd_dso("/lib/ld-musl-x86_64.so.1"));
        assert!(is_potential_tsd_dso("/usr/lib/libc.musl-x86_64.so.1"));
        assert!(!is_potential_tsd_dso("/usr/lib/libpython3.10.so"));
        assert!(!is_potential_tsd_dso("/lib/libm.so.6"));
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_extract_tsd_info_musl() {
        // Simplified musl pthread_getspecific pattern
        let code = [
            0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, // mov %fs:0x0, %rax
            0x48, 0x8b, 0x80, 0x80, 0x00, 0x00, 0x00, // mov 0x80(%rax), %rax
            0x48, 0x8b, 0x04, 0xf8, // mov (%rax,%rdi,8), %rax
            0xc3, // ret
        ];
        let result = extract_tsd_info_x86(&code);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.offset, 0x80);
        assert_eq!(info.multiplier, 8);
        assert_eq!(info.indirect, 1);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_extract_tsd_info_glibc_split() {
        // pattern: fs:0x10 -> shl -> add -> mov offset
        let code = [
            0x64, 0x48, 0x8b, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00, // mov %fs:0x10, %rax
            0x48, 0xc1, 0xe7, 0x04, // shl $0x4, %rdi
            0x48, 0x01, 0xf8, // add %rdi, %rax
            0x48, 0x8b, 0x80, 0x18, 0x03, 0x00, 0x00, // mov 0x318(%rax), %rax
            0xc3,
        ];
        let result = extract_tsd_info_x86(&code);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.offset, 0x318);
        assert_eq!(info.multiplier, 16);
        assert_eq!(info.indirect, 0);
    }
}
