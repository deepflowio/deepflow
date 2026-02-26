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

use std::collections::{hash_map::Entry, HashMap};
use std::fmt;
use std::path::Path;

use gimli::{
    BaseAddresses, CallFrameInstruction, CieOrFde, CommonInformationEntry, EhFrame, NativeEndian,
    Reader, ReaderOffset, Register, UnwindSection,
};
use log::{debug, trace};
use object::{Object, ObjectSection};

use crate::{
    error::{Error, Result},
    maps::get_memory_mappings,
};

const EH_FRAME_NAME: &'static str = ".eh_frame";

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum CfaType {
    RbpOffset, // CFA = FP + offset (RBP on x86_64, X29 on ARM64)
    RspOffset, // CFA = SP + offset (RSP on x86_64, X31 on ARM64)
    Expression,
    Unsupported,
    #[default]
    NoEntry,
}

/// Return Address recovery type for ARM64
/// On x86_64, RA is always at CFA-8 (implicitly handled in BPF code)
/// On ARM64, RA may be in LR register or saved on stack
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum RaType {
    #[default]
    CfaOffset, // RA at CFA + offset (saved on stack) - x86_64 default
    LrRegister, // ARM64: RA is in Link Register (X30), not on stack - ARM64 default
    Unsupported,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default)]
pub enum RegType {
    #[default]
    Undefined,
    SameValue,
    Offset,
    Unsupported,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct UnwindEntry {
    pub pc: u64,
    pub cfa_type: CfaType,
    pub rbp_type: RegType, // FP recovery: how to restore frame pointer
    #[cfg(target_arch = "aarch64")]
    pub ra_type: RaType, // RA recovery: how to get return address (ARM64 only)
    pub cfa_offset: i16,   // by factor of 8
    pub rbp_offset: i16,   // by factor of 8 (FP offset from CFA)
    #[cfg(target_arch = "aarch64")]
    pub ra_offset: i16, // by factor of 8 (RA offset from CFA, ARM64 only)
}

impl fmt::Display for UnwindEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(pc={:016x} ", self.pc)?;
        match self.cfa_type {
            CfaType::RbpOffset => write!(f, "cfa=fp{:+} ", (self.cfa_offset as i64) << 3)?,
            CfaType::RspOffset => write!(f, "cfa=sp{:+} ", (self.cfa_offset as i64) << 3)?,
            CfaType::Expression => write!(f, "cfa=expression ")?,
            CfaType::Unsupported => write!(f, "cfa=unsupported ")?,
            CfaType::NoEntry => write!(f, "cfa=no-entry ")?,
        }
        match self.rbp_type {
            RegType::Undefined => write!(f, "fp=undefined ")?,
            RegType::SameValue => write!(f, "fp=same ")?,
            RegType::Offset => write!(f, "fp=cfa{:+} ", (self.rbp_offset as i64) << 3)?,
            RegType::Unsupported => write!(f, "fp=unsupported ")?,
        }
        #[cfg(target_arch = "aarch64")]
        match self.ra_type {
            RaType::CfaOffset => write!(f, "ra=cfa{:+})", (self.ra_offset as i64) << 3)?,
            RaType::LrRegister => write!(f, "ra=lr)")?,
            RaType::Unsupported => write!(f, "ra=unsupported)")?,
        }
        #[cfg(not(target_arch = "aarch64"))]
        write!(f, ")")?;
        Ok(())
    }
}

impl PartialEq for UnwindEntry {
    fn eq(&self, other: &Self) -> bool {
        self.pc.eq(&other.pc)
    }
}

impl Eq for UnwindEntry {}

impl Ord for UnwindEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.pc.cmp(&other.pc)
    }
}

impl PartialOrd for UnwindEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// Architecture-specific DWARF register IDs
// For x86_64: RBP=6, RSP=7 (System V AMD64 ABI)
// For ARM64: FP/X29=29, SP=31, LR/X30=30 (DWARF for ARM Architecture)

#[cfg(target_arch = "x86_64")]
mod arch_regs {
    pub const FP: u16 = 6; // RBP - Frame Pointer
    pub const SP: u16 = 7; // RSP - Stack Pointer
}

#[cfg(target_arch = "aarch64")]
mod arch_regs {
    pub const FP: u16 = 29; // X29/FP - Frame Pointer
    pub const SP: u16 = 31; // SP - Stack Pointer
    pub const LR: u16 = 30; // X30/LR - Link Register (holds return address)
}

// Fallback for other architectures (compilation will fail with meaningful error)
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod arch_regs {
    pub const FP: u16 = 0;
    pub const SP: u16 = 0;
    compile_error!("Unsupported architecture for DWARF unwinding");
}

#[cfg(target_arch = "aarch64")]
use arch_regs::LR as REG_ID_LR;
use arch_regs::{FP as REG_ID_FP, SP as REG_ID_SP};

// Legacy aliases for backward compatibility in existing code
const REG_ID_RBP: u16 = REG_ID_FP;
const REG_ID_RSP: u16 = REG_ID_SP;

impl UnwindEntry {
    #[cfg(target_arch = "aarch64")]
    fn new<S, R>(
        section: &S,
        bases: &BaseAddresses,
        cie: &CommonInformationEntry<R>,
        default_ra_type: RaType,
    ) -> Result<Self>
    where
        R: Reader,
        S: UnwindSection<R>,
    {
        let mut sm = Self {
            ra_type: default_ra_type,
            ..Default::default()
        };
        let mut ins_iter = cie.instructions(section, bases);
        while let Some(ins) = ins_iter.next()? {
            sm.update(cie, &ins);
        }
        Ok(sm)
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn new<S, R>(
        section: &S,
        bases: &BaseAddresses,
        cie: &CommonInformationEntry<R>,
        _default_ra_type: RaType,
    ) -> Result<Self>
    where
        R: Reader,
        S: UnwindSection<R>,
    {
        let mut sm = Self::default();
        let mut ins_iter = cie.instructions(section, bases);
        while let Some(ins) = ins_iter.next()? {
            sm.update(cie, &ins);
        }
        Ok(sm)
    }

    fn set_pc(&mut self, pc: u64) {
        self.pc = pc;
    }

    fn set_cfa_reg(&mut self, reg: &Register) {
        match reg.0 {
            REG_ID_RBP => self.cfa_type = CfaType::RbpOffset,
            REG_ID_RSP => self.cfa_type = CfaType::RspOffset,
            _ => self.cfa_type = CfaType::Unsupported,
        }
    }

    fn update<R, T>(&mut self, cie: &CommonInformationEntry<R>, ins: &CallFrameInstruction<T>)
    where
        R: Reader,
        T: ReaderOffset,
    {
        match ins {
            // row instructions
            CallFrameInstruction::SetLoc { address } => {
                self.pc = *address;
            }
            CallFrameInstruction::AdvanceLoc { delta } => {
                self.pc += *delta as u64 * cie.code_alignment_factor();
            }
            // cfa instructions
            CallFrameInstruction::DefCfa { register, offset } => {
                self.set_cfa_reg(register);
                self.cfa_offset = (offset >> 3) as i16;
            }
            CallFrameInstruction::DefCfaSf {
                register,
                factored_offset,
            } => {
                self.set_cfa_reg(register);
                self.cfa_offset = ((factored_offset * cie.data_alignment_factor()) >> 3) as i16;
            }
            CallFrameInstruction::DefCfaRegister { register } => self.set_cfa_reg(register),
            CallFrameInstruction::DefCfaOffset { offset } => self.cfa_offset = (offset >> 3) as i16,
            CallFrameInstruction::DefCfaOffsetSf { factored_offset } => {
                self.cfa_offset =
                    ((*factored_offset as i64 * cie.data_alignment_factor()) >> 3) as i16;
            }
            CallFrameInstruction::DefCfaExpression { expression } => {
                // TBD
                let _ = expression;
                self.cfa_type = CfaType::Expression;
                self.cfa_offset = 0;
            }
            // FP register instructions (RBP on x86_64, X29 on ARM64)
            CallFrameInstruction::Undefined { register } if register.0 == REG_ID_RBP => {
                self.rbp_type = RegType::Undefined;
                self.rbp_offset = 0;
            }
            CallFrameInstruction::SameValue { register } if register.0 == REG_ID_RBP => {
                self.rbp_type = RegType::SameValue;
                self.rbp_offset = 0;
            }
            CallFrameInstruction::Offset {
                register,
                factored_offset,
            } if register.0 == REG_ID_RBP => {
                self.rbp_type = RegType::Offset;
                self.rbp_offset =
                    ((*factored_offset as i64 * cie.data_alignment_factor()) >> 3) as i16;
            }
            CallFrameInstruction::OffsetExtendedSf {
                register,
                factored_offset,
            } if register.0 == REG_ID_RBP => {
                self.rbp_type = RegType::Offset;
                self.rbp_offset =
                    ((*factored_offset as i64 * cie.data_alignment_factor()) >> 3) as i16;
            }
            // unsupported FP register instructions
            CallFrameInstruction::ValOffset { register, .. } if register.0 == REG_ID_RBP => {
                self.rbp_type = RegType::Unsupported;
                self.rbp_offset = 0;
            }
            CallFrameInstruction::ValOffsetSf { register, .. } if register.0 == REG_ID_RBP => {
                self.rbp_type = RegType::Unsupported;
                self.rbp_offset = 0;
            }
            CallFrameInstruction::Register { dest_register, .. }
                if dest_register.0 == REG_ID_RBP =>
            {
                self.rbp_type = RegType::Unsupported;
                self.rbp_offset = 0;
            }
            CallFrameInstruction::Expression { register, .. } if register.0 == REG_ID_RBP => {
                self.rbp_type = RegType::Unsupported;
                self.rbp_offset = 0;
            }
            // ARM64 LR (Link Register / X30) tracking for return address
            // When LR has SameValue rule, return address is in LR register
            // When LR has Offset rule, RA is saved on stack at CFA + offset
            #[cfg(target_arch = "aarch64")]
            CallFrameInstruction::SameValue { register } if register.0 == REG_ID_LR => {
                self.ra_type = RaType::LrRegister;
                self.ra_offset = 0;
            }
            #[cfg(target_arch = "aarch64")]
            CallFrameInstruction::Offset {
                register,
                factored_offset,
            } if register.0 == REG_ID_LR => {
                self.ra_type = RaType::CfaOffset;
                self.ra_offset =
                    ((*factored_offset as i64 * cie.data_alignment_factor()) >> 3) as i16;
            }
            #[cfg(target_arch = "aarch64")]
            CallFrameInstruction::OffsetExtendedSf {
                register,
                factored_offset,
            } if register.0 == REG_ID_LR => {
                self.ra_type = RaType::CfaOffset;
                self.ra_offset =
                    ((*factored_offset as i64 * cie.data_alignment_factor()) >> 3) as i16;
            }
            #[cfg(target_arch = "aarch64")]
            CallFrameInstruction::Undefined { register } if register.0 == REG_ID_LR => {
                // LR undefined usually means this is a stop frame (entry point)
                self.ra_type = RaType::Unsupported;
                self.ra_offset = 0;
            }
            _ => (),
        }
    }
}

type RegState = (RegType, i16);
#[cfg(target_arch = "aarch64")]
type RaState = (RaType, i16);

struct StateMachine {
    entry: UnwindEntry,
    initial_rbp: RegState,
    #[cfg(target_arch = "aarch64")]
    initial_ra: RaState,
    reg_stack: Vec<UnwindEntry>,
}

impl StateMachine {
    fn new(entry: UnwindEntry) -> Self {
        Self {
            entry,
            initial_rbp: (entry.rbp_type, entry.rbp_offset),
            #[cfg(target_arch = "aarch64")]
            initial_ra: (entry.ra_type, entry.ra_offset),
            reg_stack: Default::default(),
        }
    }

    fn set_pc(&mut self, pc: u64) {
        self.entry.set_pc(pc);
    }

    fn update<R, T>(&mut self, cie: &CommonInformationEntry<R>, ins: &CallFrameInstruction<T>)
    where
        R: Reader,
        T: ReaderOffset,
    {
        match ins {
            CallFrameInstruction::Restore { register } => {
                if register.0 == REG_ID_RBP {
                    (self.entry.rbp_type, self.entry.rbp_offset) = self.initial_rbp;
                }
                // ARM64: Also handle LR restore
                #[cfg(target_arch = "aarch64")]
                if register.0 == REG_ID_LR {
                    (self.entry.ra_type, self.entry.ra_offset) = self.initial_ra;
                }
            }
            CallFrameInstruction::RememberState => {
                self.reg_stack.push(self.entry);
            }
            CallFrameInstruction::RestoreState => {
                if let Some(stack_state) = self.reg_stack.pop() {
                    self.entry = UnwindEntry {
                        pc: self.entry.pc,
                        ..stack_state
                    };
                }
            }
            _ => self.entry.update(cie, ins),
        }
    }
}

pub fn read_unwind_entries(data: &[u8]) -> Result<Vec<UnwindEntry>> {
    let file = object::File::parse(data)?;
    let Some(eh_section) = file.section_by_name(EH_FRAME_NAME) else {
        return Err(Error::NoEhFrame);
    };
    let eh_frame = EhFrame::new(eh_section.data()?, NativeEndian);
    let ba = BaseAddresses::default().set_eh_frame(eh_section.address());

    // Set default return address type based on target architecture.
    // On ARM64, return address is in LR by default (until explicitly saved to stack).
    // On x86_64, return address is always at CFA-8.
    #[cfg(target_arch = "aarch64")]
    let default_ra_type = RaType::LrRegister;
    #[cfg(not(target_arch = "aarch64"))]
    let default_ra_type = RaType::CfaOffset;

    // Create a default UnwindEntry with architecture-specific ra_type
    #[cfg(target_arch = "aarch64")]
    let make_default_entry = |pc: u64| UnwindEntry {
        pc,
        ra_type: default_ra_type,
        ..Default::default()
    };
    #[cfg(not(target_arch = "aarch64"))]
    let make_default_entry = |pc: u64| UnwindEntry {
        pc,
        ..Default::default()
    };

    // Find the maximum address of executable sections (.text, .plt, etc.)
    // to determine the actual code range, not just DWARF coverage
    let mut max_executable_addr = 0u64;
    for section in file.sections() {
        if section.kind() == object::SectionKind::Text {
            let section_end = section.address().saturating_add(section.size());
            max_executable_addr = max_executable_addr.max(section_end);
        }
    }

    let mut unwind_entries = vec![];
    // represent pc ranges without dwarf entries
    let mut holes = vec![make_default_entry(0)];

    let mut cies = HashMap::new();
    let mut cie_states = HashMap::new();
    let mut entries = eh_frame.entries(&ba);
    while let Some(entry) = entries.next()? {
        if let CieOrFde::Fde(pfde) = entry {
            let fde = pfde.parse(|_, ba, offset| {
                cies.entry(offset)
                    .or_insert_with(|| eh_frame.cie_from_offset(ba, offset))
                    .clone()
            })?;

            // calculate holes
            let fde_start = fde.initial_address();
            let fde_end = fde.end_address();
            match holes.binary_search_by_key(&fde_start, |entry| entry.pc) {
                Ok(index) if index == holes.len() - 1 => holes[index].pc = fde.end_address(),
                Ok(index) => {
                    let next_hole = &holes[index + 1];
                    if next_hole.pc == fde_end {
                        holes.remove(index);
                    } else if next_hole.pc > fde_end {
                        holes[index].pc = fde_end;
                    } else {
                        // the fde crossed multiple holes, is this possible?
                        unreachable!();
                    }
                }
                Err(index) if index >= holes.len() => holes.push(make_default_entry(fde_end)),
                Err(index) => {
                    // we have holes[index - 1].pc < fde_start and holes[index].pc > fde_start here
                    let next_hole = &holes[index];
                    if next_hole.pc == fde_end {
                        // do nothing
                    } else if next_hole.pc > fde_end {
                        holes.insert(index, make_default_entry(fde_end));
                    } else {
                        match (&holes[index..]).binary_search_by_key(&fde_end, |entry| entry.pc) {
                            Ok(offset) => {
                                holes.drain(index..index + offset);
                            }
                            Err(offset) => {
                                // we have offset >= 1 here because next_hole.pc < fde_end
                                holes.drain(index..index + offset - 1);
                                holes[index].pc = fde_end;
                            }
                        }
                    }
                }
            }

            // copy here because CIE state is for all FDEs
            let entry: UnwindEntry = match cie_states.entry(pfde.cie_offset()) {
                Entry::Occupied(o) => *o.get(),
                Entry::Vacant(v) => *v.insert(UnwindEntry::new(
                    &eh_frame,
                    &ba,
                    fde.cie(),
                    default_ra_type,
                )?),
            };
            let mut sm = StateMachine::new(entry);
            sm.set_pc(fde.initial_address());
            let mut ins_iter = fde.instructions(&eh_frame, &ba);

            // On ARM64, tolerate unknown CFI instructions by skipping problematic FDEs.
            // ARM64 binaries may use newer CFI instructions (e.g., for PAC/BTI) not yet
            // supported by gimli. On x86_64, the CFI instruction set is stable and fully
            // supported, so we keep the original strict behavior.
            #[allow(unused_mut)]
            let mut fde_ok = true;
            loop {
                match ins_iter.next() {
                    Ok(None) => break,
                    Ok(Some(ins)) => {
                        if matches!(
                            ins,
                            CallFrameInstruction::AdvanceLoc { .. }
                                | CallFrameInstruction::SetLoc { .. }
                        ) {
                            unwind_entries.push(sm.entry);
                        }
                        sm.update(fde.cie(), &ins);
                    }
                    #[cfg(target_arch = "aarch64")]
                    Err(_e) => {
                        fde_ok = false;
                        break;
                    }
                    #[cfg(not(target_arch = "aarch64"))]
                    Err(e) => return Err(e.into()),
                }
            }

            if fde_ok {
                unwind_entries.push(sm.entry);
            }
        }
    }
    unwind_entries.extend(holes);
    unwind_entries.sort_unstable();

    // Extend coverage to the full executable section range
    // For code beyond DWARF coverage (e.g., PLT, hand-written asm),
    // add a synthetic entry that reuses the last entry's unwinding rules
    if max_executable_addr > 0 {
        let last_dwarf_pc = unwind_entries
            .iter()
            .rev()
            .find(|e| e.cfa_type != CfaType::NoEntry)
            .map(|e| e.pc)
            .unwrap_or(0);

        if max_executable_addr > last_dwarf_pc {
            // Add synthetic entry at max_executable_addr using last available rules
            if let Some(last_entry) = unwind_entries
                .iter()
                .rev()
                .find(|e| e.cfa_type != CfaType::NoEntry)
            {
                let mut extended_entry = *last_entry;
                extended_entry.pc = max_executable_addr;
                unwind_entries.push(extended_entry);
                // Note: No need to re-sort since we're adding at the end
            }
        }
    }

    Ok(unwind_entries)
}

pub fn frame_pointer_heuristic_check(pid: u32) -> bool {
    let mappings = match get_memory_mappings(pid) {
        Ok(m) => m,
        Err(e) => {
            debug!("failed loading maps for process#{pid}: {e}");
            return false;
        }
    };
    for m in mappings {
        let path = Path::new(&m.path);
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if name.starts_with("libc.")
                || name.starts_with("libc-")
                || name.starts_with("libstdc++.")
            {
                trace!("process#{pid} may not have frame pointer enabled");
                return false;
            }
        }
    }
    trace!("process#{pid} may have frame pointer enabled");
    true
}
