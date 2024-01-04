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

use std::fmt;
use std::mem::forget;

use enum_dispatch::enum_dispatch;
use num_enum::IntoPrimitive;
use pcap_sys::bpf_insn;

#[enum_dispatch]
#[derive(Clone)]
pub enum BpfSyntax {
    LoadAbsolute(LoadAbsolute),
    LoadConstant(LoadConstant),
    LoadIndirect(LoadIndirect),
    LoadExtension(LoadExtension),
    JumpIf(JumpIf),
    ALUOpConstant(ALUOpConstant),
    RetConstant(RetConstant),
    Txa(Txa),
}

impl fmt::Display for BpfSyntax {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadAbsolute(e) => write!(f, "{}", e),
            Self::LoadConstant(e) => write!(f, "{}", e),
            Self::LoadIndirect(e) => write!(f, "{}", e),
            Self::LoadExtension(e) => write!(f, "{}", e),
            Self::JumpIf(e) => write!(f, "{}", e),
            Self::ALUOpConstant(e) => write!(f, "{}", e),
            Self::RetConstant(e) => write!(f, "{}", e),
            Self::Txa(t) => write!(f, "{t}"),
        }
    }
}

impl BpfSyntax {
    pub fn to_instruction(&self) -> RawInstruction {
        match self {
            Self::LoadAbsolute(e) => e.to_instruction(),
            Self::LoadConstant(e) => e.to_instruction(),
            Self::LoadIndirect(e) => e.to_instruction(),
            Self::LoadExtension(e) => e.to_instruction(),
            Self::JumpIf(e) => e.to_instruction(),
            Self::ALUOpConstant(e) => e.to_instruction(),
            Self::RetConstant(e) => e.to_instruction(),
            Self::Txa(t) => t.to_instruction(),
        }
    }
}

#[enum_dispatch(BpfSyntax)]
trait Instruction: fmt::Display {
    fn to_instruction(&self) -> RawInstruction;
}

#[repr(C)]
#[derive(Clone, Default)]
pub struct RawInstruction {
    op: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl From<bpf_insn> for RawInstruction {
    fn from(ins: bpf_insn) -> Self {
        Self {
            op: ins.code,
            jt: ins.jt,
            jf: ins.jf,
            k: ins.k,
        }
    }
}

#[repr(C)]
pub struct Prog {
    len: u16,
    filter: *mut RawInstruction,
}

impl Prog {
    pub fn new(ins: Vec<RawInstruction>) -> Prog {
        let mut ins = ins.into_boxed_slice();
        let len = ins.len();
        let ptr = ins.as_mut_ptr();

        forget(ins);

        Prog {
            len: len as u16,
            filter: ptr,
        }
    }
}

impl Drop for Prog {
    fn drop(&mut self) {
        unsafe {
            let len = self.len as usize;
            let ptr = self.filter;
            Vec::from_raw_parts(ptr, len, len);
        }
    }
}

#[derive(Clone, Debug)]
pub struct LoadAbsolute {
    pub off: u32,
    pub size: u32, // 1, 2 or 4
}

// -0x1000
//const EXT_OFFSET: i32 = (-0x1000);
const EXT_OFFSET_MIN: u32 = 0xfffff000;

const OP_ADDRMODE_IMMEDIATE: u16 = 0;
const OP_ADDRMODE_ABSOLUTE: u16 = 1 << 5;
const OP_ADDRMODE_INDIRECT: u16 = 2 << 5;
const OP_ADDRMODE_SCRATCH: u16 = 3 << 5;
const OP_ADDRMODE_PACKETLEN: u16 = 4 << 5;
const OP_ADDRMODE_MEMSHIFT: u16 = 5 << 5;

const OP_CLS_LOAD_A: u16 = 0;
const OP_CLS_LOAD_X: u16 = 1;
const OP_CLS_STORE_A: u16 = 2;
const OP_CLS_STORE_X: u16 = 3;
const OP_CLS_ALU: u16 = 4;
pub const OP_CLS_JUMP: u16 = 5;
pub const OP_CLS_RETURN: u16 = 6;
const OP_CLS_MISC: u16 = 7;
const OP_MISC_TXA: u16 = 128;

const OP_LOAD_WIDTH_4: u16 = 0;
const OP_LOAD_WIDTH_2: u16 = 1 << 3;
const OP_LOAD_WIDTH_1: u16 = 2 << 3;

#[derive(Copy, Clone, Debug)]
pub enum Register {
    RegA,
    RegX,
}

fn load_to_instruction(dst: Register, size: u32, mode: u16, k: u32) -> RawInstruction {
    let cls = match dst {
        Register::RegA => OP_CLS_LOAD_A,
        Register::RegX => OP_CLS_LOAD_X,
    };
    let word_size = match size {
        1 => OP_LOAD_WIDTH_1,
        2 => OP_LOAD_WIDTH_2,
        4 => OP_LOAD_WIDTH_4,
        _ => panic!("unknown instruction: {:?}", size),
    };

    RawInstruction {
        op: cls | word_size | mode,
        k,
        ..Default::default()
    }
}

impl fmt::Display for LoadAbsolute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.size {
            1 => write!(f, "ldb [{}]", self.off),
            2 => write!(f, "ldh [{}]", self.off),
            4 => {
                if self.off > EXT_OFFSET_MIN {
                    panic!("Use LoadExtension.");
                }
                write!(f, "ld [{}]", self.off)
            }
            _ => panic!("Invalid size."),
        }
    }
}

impl Instruction for LoadAbsolute {
    fn to_instruction(&self) -> RawInstruction {
        load_to_instruction(Register::RegA, self.size, OP_ADDRMODE_ABSOLUTE, self.off)
    }
}

#[derive(Clone, Debug)]
pub struct LoadConstant {
    pub dst: Register,
    pub val: u32,
}

impl fmt::Display for LoadConstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.dst {
            Register::RegA => write!(f, "ld #{}", self.val),
            Register::RegX => write!(f, "ldx #{}", self.val),
        }
    }
}

impl Instruction for LoadConstant {
    fn to_instruction(&self) -> RawInstruction {
        return load_to_instruction(self.dst, 4, OP_ADDRMODE_IMMEDIATE, self.val);
    }
}

#[derive(Clone, Debug)]
pub struct LoadIndirect {
    pub off: u32,
    pub size: u32, // 1, 2 or 4
}

impl fmt::Display for LoadIndirect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.size {
            1 => write!(f, "ldb [x + {}]", self.off),
            2 => write!(f, "ldh [x + {}]", self.off),
            4 => write!(f, "ld [x + {}]", self.off),
            _ => panic!("unknown instruction: {:?}", self),
        }
    }
}

impl Instruction for LoadIndirect {
    fn to_instruction(&self) -> RawInstruction {
        return load_to_instruction(Register::RegA, self.size, OP_ADDRMODE_INDIRECT, self.off);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, IntoPrimitive)]
#[repr(u32)]
pub enum Extension {
    ExtProto = 0,
    ExtLen = 1,
    ExtType = 4,
    ExtPayloadOffset = 52,
    ExtInterfaceIndex = 8,
    ExtNetlinkAttr = 12,
    ExtNetlinkAttrNested = 16,
    ExtMark = 20,
    ExtQueue = 24,
    ExtLinkLayerType = 28,
    ExtRXHash = 32,
    ExtCPUID = 36,
    ExtVLANTag = 44,
    ExtVLANTagPresent = 48,
    ExtVLANProto = 60,
    ExtRand = 56,
}

#[derive(Clone)]
pub struct LoadExtension {
    pub num: Extension,
}

impl fmt::Display for LoadExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.num {
            Extension::ExtLen => write!(f, "ld #len"),
            Extension::ExtProto => write!(f, "ld #proto"),
            Extension::ExtType => write!(f, "ld #type"),
            Extension::ExtPayloadOffset => write!(f, "ld #poff"),
            Extension::ExtInterfaceIndex => write!(f, "ld #ifidx"),
            Extension::ExtNetlinkAttr => write!(f, "ld #nla"),
            Extension::ExtNetlinkAttrNested => write!(f, "ld #nlan"),
            Extension::ExtMark => write!(f, "ld #mark"),
            Extension::ExtQueue => write!(f, "ld #queue"),
            Extension::ExtLinkLayerType => write!(f, "ld #hatype"),
            Extension::ExtRXHash => write!(f, "ld #rxhash"),
            Extension::ExtCPUID => write!(f, "ld #cpu"),
            Extension::ExtVLANTag => write!(f, "ld #vlan_tci"),
            Extension::ExtVLANTagPresent => write!(f, "ld #vlan_avail"),
            Extension::ExtVLANProto => write!(f, "ld #vlan_tpid"),
            Extension::ExtRand => write!(f, "ld #rand"),
        }
    }
}

impl Instruction for LoadExtension {
    fn to_instruction(&self) -> RawInstruction {
        if self.num == Extension::ExtLen {
            return load_to_instruction(Register::RegA, 4, OP_ADDRMODE_PACKETLEN, 0);
        }
        return load_to_instruction(
            Register::RegA,
            4,
            OP_ADDRMODE_ABSOLUTE,
            u32::from(self.num) + EXT_OFFSET_MIN,
        );
    }
}

#[derive(Copy, Clone)]
pub enum JumpTest {
    // K == A
    JumpEqual,
    // K != A
    JumpNotEqual,
    // K > A
    JumpGreaterThan,
    // K < A
    JumpLessThan,
    // K >= A
    JumpGreaterOrEqual,
    // K <= A
    JumpLessOrEqual,
    // K & A != 0
    JumpBitsSet,
    // K & A == 0
    JumpBitsNotSet,
}

#[derive(Copy, Clone)]
pub struct JumpIf {
    pub cond: JumpTest,
    pub val: u32,
    pub skip_true: u8,
    pub skip_false: u8,
}

impl Default for JumpIf {
    fn default() -> Self {
        Self {
            cond: JumpTest::JumpEqual,
            val: 0,
            skip_true: 0,
            skip_false: 0,
        }
    }
}

const OP_JUMP_ALWAYS: u16 = 0;
pub const OP_JUMP_EQUAL: u16 = 1 << 4;
const OP_JUMP_GT: u16 = 2 << 4;
const OP_JUMP_GE: u16 = 3 << 4;
const OP_JUMP_SET: u16 = 4 << 4;

fn jump_to_instruction(
    test: JumpTest,
    operand: u16,
    k: u32,
    skip_true: u8,
    skip_false: u8,
) -> RawInstruction {
    let (cond, flip) = match test {
        JumpTest::JumpEqual => (OP_JUMP_EQUAL, false),
        JumpTest::JumpNotEqual => (OP_JUMP_EQUAL, true),
        JumpTest::JumpGreaterThan => (OP_JUMP_GT, false),
        JumpTest::JumpLessThan => (OP_JUMP_GE, true),
        JumpTest::JumpGreaterOrEqual => (OP_JUMP_GE, false),
        JumpTest::JumpLessOrEqual => (OP_JUMP_GT, true),
        JumpTest::JumpBitsSet => (OP_JUMP_SET, false),
        JumpTest::JumpBitsNotSet => (OP_JUMP_SET, true),
    };

    let (jt, jf) = if flip {
        (skip_false, skip_true)
    } else {
        (skip_true, skip_false)
    };

    RawInstruction {
        op: OP_CLS_JUMP | cond | operand,
        jt,
        jf,
        k,
    }
}

fn conditional_jump(
    f: &mut fmt::Formatter<'_>,
    operand: &str,
    skip_true: u8,
    skip_false: u8,
    positive_jump: &str,
    negative_jump: &str,
) -> fmt::Result {
    if skip_true > 0 {
        if skip_false > 0 {
            return write!(
                f,
                "{} {},{},{}",
                positive_jump, operand, skip_true, skip_false
            );
        }
        return write!(f, "{} {},{}", positive_jump, operand, skip_true);
    }
    return write!(f, "{} {},{}", negative_jump, operand, skip_false);
}

fn jump_to_string(
    f: &mut fmt::Formatter<'_>,
    cond: JumpTest,
    operand: &str,
    skip_true: u8,
    skip_false: u8,
) -> fmt::Result {
    match cond {
        JumpTest::JumpEqual => conditional_jump(f, operand, skip_true, skip_false, "jeq", "jneq"),
        // write!(f, "jneq {},{}", operand, skip_true),
        JumpTest::JumpNotEqual => {
            conditional_jump(f, operand, skip_true, skip_false, "jneq", "jeq")
        }
        JumpTest::JumpGreaterThan => {
            conditional_jump(f, operand, skip_true, skip_false, "jgt", "jle")
        }
        JumpTest::JumpLessThan => write!(f, "jlt {},{}", operand, skip_true),
        JumpTest::JumpGreaterOrEqual => {
            conditional_jump(f, operand, skip_true, skip_false, "jge", "jlt")
        }
        JumpTest::JumpLessOrEqual => write!(f, "jle {},{}", operand, skip_true),
        JumpTest::JumpBitsSet => {
            if skip_false > 0 {
                return write!(f, "jset {},{},{}", operand, skip_true, skip_false);
            }
            return write!(f, "jset {},{}", operand, skip_true);
        }
        JumpTest::JumpBitsNotSet => {
            jump_to_string(f, JumpTest::JumpBitsSet, operand, skip_false, skip_true)
        }
    }
}

impl fmt::Display for JumpIf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        jump_to_string(
            f,
            self.cond,
            format!("#{}", self.val).as_str(),
            self.skip_true,
            self.skip_false,
        )
    }
}

impl Instruction for JumpIf {
    fn to_instruction(&self) -> RawInstruction {
        return jump_to_instruction(
            self.cond,
            OP_OPERAND_CONSTANT,
            self.val,
            self.skip_true,
            self.skip_false,
        );
    }
}

#[derive(Clone)]
pub struct RetConstant {
    pub val: u32,
}

const OP_RET_SRC_CONSTANT: u16 = 0;
const OP_RET_SRC_A: u16 = 1 << 4;

impl fmt::Display for RetConstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ret #{}", self.val)
    }
}

impl Instruction for RetConstant {
    fn to_instruction(&self) -> RawInstruction {
        return RawInstruction {
            op: OP_CLS_RETURN | OP_RET_SRC_CONSTANT,
            k: self.val,
            ..Default::default()
        };
    }
}

pub const ALU_OP_ADD: u16 = 0;
pub const ALU_OP_SUB: u16 = 1 << 4;
pub const ALU_OP_MUL: u16 = 2 << 4;
pub const ALU_OP_DIV: u16 = 3 << 4;
pub const ALU_OP_OR: u16 = 4 << 4;
pub const ALU_OP_AND: u16 = 5 << 4;
pub const ALU_OP_SHIFT_LEFT: u16 = 6 << 4;
pub const ALU_OP_SHIFT_RIGHT: u16 = 7 << 4;
pub const ALU_OP_NEG: u16 = 8 << 4; // Not excepted.
pub const ALU_OP_MOD: u16 = 9 << 4;
pub const ALU_OP_XOR: u16 = 10 << 4;

const OP_OPERAND_CONSTANT: u16 = 0;
const OP_OPERAND_X: u16 = 1 << 3;

#[derive(Clone, Debug)]
pub struct ALUOpConstant {
    pub op: u16,
    pub val: u32,
}

impl fmt::Display for ALUOpConstant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.op {
            ALU_OP_ADD => write!(f, "add #{}", self.val),
            ALU_OP_SUB => write!(f, "sub #{}", self.val),
            ALU_OP_MUL => write!(f, "mul #{}", self.val),
            ALU_OP_DIV => write!(f, "div #{}", self.val),
            ALU_OP_MOD => write!(f, "mod #{}", self.val),
            ALU_OP_OR => write!(f, "or #{}", self.val),
            ALU_OP_AND => write!(f, "and #{}", self.val),
            ALU_OP_SHIFT_LEFT => write!(f, "lsh #{}", self.val),
            ALU_OP_SHIFT_RIGHT => write!(f, "rsh #{}", self.val),
            ALU_OP_XOR => write!(f, "xor #{}", self.val),
            _ => panic!("unknown instruction: {:?}", self),
        }
    }
}

impl Instruction for ALUOpConstant {
    fn to_instruction(&self) -> RawInstruction {
        RawInstruction {
            op: OP_CLS_ALU | self.op | OP_OPERAND_CONSTANT,
            k: self.val,
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy)]
pub struct Txa;

impl fmt::Display for Txa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "txa")
    }
}

impl Instruction for Txa {
    fn to_instruction(&self) -> RawInstruction {
        RawInstruction {
            op: OP_CLS_MISC | OP_MISC_TXA,
            ..Default::default()
        }
    }
}
