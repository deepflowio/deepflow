use std::collections::{hash_map::Entry, HashMap};
use std::fmt;
use std::fs;
use std::path::Path;

use gimli::{
    BaseAddresses, CallFrameInstruction, CieOrFde, CommonInformationEntry, EhFrame, NativeEndian,
    Reader, ReaderOffset, Register, UnwindSection,
};
use object::{Object, ObjectSection};

use super::error::{Error, Result};

pub const ENTRIES_PER_SHARD: usize = 250000;

const EH_FRAME_NAME: &'static str = ".eh_frame";

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ShardInfo {
    pub id: i32,
    pub pc_min: u64,
    pub pc_max: u64,
}

impl Default for ShardInfo {
    fn default() -> Self {
        Self {
            id: -1,
            pc_min: u64::MAX,
            pc_max: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct ShardInfoList {
    pub info: [ShardInfo; 40],
}

impl Default for ShardInfoList {
    fn default() -> Self {
        Self {
            info: [ShardInfo::default(); 40],
        }
    }
}

const SHARD_INFO_STRUCT_SIZE: usize = std::mem::size_of::<ShardInfoList>();

impl ShardInfoList {
    pub fn as_slice(&self) -> &[u8; SHARD_INFO_STRUCT_SIZE] {
        // SAFETY:
        // * `UnwindEntryShard` has the same size as `[u8; MY_STRUCT_SIZE]`.
        // * `[u8; SHARD_STRUCT_SIZE]` has no alignment requirement.
        // * Since it is `repr(C)`, this type has no padding.
        unsafe { &*(self as *const ShardInfoList as *const [u8; SHARD_INFO_STRUCT_SIZE]) }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct UnwindEntryShard {
    pub len: u32,
    pub entries: [UnwindEntry; ENTRIES_PER_SHARD],
}

impl Default for UnwindEntryShard {
    fn default() -> Self {
        Self {
            len: 0,
            entries: [UnwindEntry::default(); ENTRIES_PER_SHARD],
        }
    }
}

const SHARD_STRUCT_SIZE: usize = std::mem::size_of::<UnwindEntryShard>();

impl UnwindEntryShard {
    pub fn as_slice(&self) -> &[u8; SHARD_STRUCT_SIZE] {
        // SAFETY:
        // * `UnwindEntryShard` has the same size as `[u8; MY_STRUCT_SIZE]`.
        // * `[u8; SHARD_STRUCT_SIZE]` has no alignment requirement.
        // * Since it is `repr(C)`, this type has no padding.
        unsafe { &*(self as *const UnwindEntryShard as *const [u8; SHARD_STRUCT_SIZE]) }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default)]
pub enum CfaType {
    RbpOffset,
    RspOffset,
    Expression,
    #[default]
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
    pub rbp_type: RegType,
    pub cfa_offset: i16, // by factor of 8
    pub rbp_offset: i16, // by factor of 8
}

impl fmt::Display for UnwindEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(pc={:016x} ", self.pc)?;
        match self.cfa_type {
            CfaType::RbpOffset => write!(f, "cfa=rbp{:+} ", (self.cfa_offset as i64) << 3)?,
            CfaType::RspOffset => write!(f, "cfa=rsp{:+} ", (self.cfa_offset as i64) << 3)?,
            CfaType::Expression => write!(f, "cfa=expression ")?,
            CfaType::Unsupported => write!(f, "cfa=unsupported ")?,
        }
        match self.rbp_type {
            RegType::Undefined => write!(f, "rbp=undefined)"),
            RegType::SameValue => write!(f, "rbp=rbp)"),
            RegType::Offset => write!(f, "rbp=cfa{:+})", (self.rbp_offset as i64) << 3),
            RegType::Unsupported => write!(f, "rbp=unsupported)"),
        }
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

const REG_ID_RBP: u16 = 6;
const REG_ID_RSP: u16 = 7;

impl UnwindEntry {
    fn new<S, R>(
        section: &S,
        bases: &BaseAddresses,
        cie: &CommonInformationEntry<R>,
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
                self.cfa_type = CfaType::Expression;
                self.cfa_offset = 0;
            }
            // register instructions: only care about RBP
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
            // unsupported register instructions
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
            _ => (),
        }
    }
}

type RegState = (RegType, i16);

struct StateMachine {
    entry: UnwindEntry,
    initial_rbp: RegState,
    reg_stack: Vec<UnwindEntry>,
}

impl StateMachine {
    fn new(entry: UnwindEntry) -> Self {
        Self {
            entry,
            initial_rbp: (entry.rbp_type, entry.rbp_offset),
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

pub fn read_unwind_entries<P: AsRef<Path>>(filename: P) -> Result<Vec<UnwindEntry>> {
    let data = fs::read(filename.as_ref())?;
    let file = object::File::parse(&*data)?;
    let Some(eh_section) = file
        .sections()
        .find(|s| s.name().map(|n| n == EH_FRAME_NAME).unwrap_or(false))
    else {
        return Err(Error::NoEhFrame);
    };
    let eh_frame = EhFrame::new(eh_section.data()?, NativeEndian);
    let ba = BaseAddresses::default().set_eh_frame(eh_section.address());

    let mut unwind_entries = vec![];

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
            // copy here because CIE state is for all FDEs
            let entry: UnwindEntry = match cie_states.entry(pfde.cie_offset()) {
                Entry::Occupied(o) => *o.get(),
                Entry::Vacant(v) => *v.insert(UnwindEntry::new(&eh_frame, &ba, fde.cie())?),
            };
            let mut sm = StateMachine::new(entry);
            sm.set_pc(fde.initial_address());
            let mut ins_iter = fde.instructions(&eh_frame, &ba);
            while let Some(ins) = ins_iter.next()? {
                if matches!(
                    ins,
                    CallFrameInstruction::AdvanceLoc { .. } | CallFrameInstruction::SetLoc { .. }
                ) {
                    unwind_entries.push(sm.entry);
                }
                sm.update(fde.cie(), &ins);
            }
            unwind_entries.push(sm.entry);
        }
    }
    unwind_entries.sort_unstable();
    Ok(unwind_entries)
}
