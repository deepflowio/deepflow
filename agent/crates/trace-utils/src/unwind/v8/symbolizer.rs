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

//! V8 JavaScript engine symbolization.
//!
//! This module provides user-space symbolization for V8/Node.js stack frames by reading
//! and parsing V8 heap objects (JSFunction, SharedFunctionInfo, Code, Script, etc.) from
//! the target process memory.
//!
//! Architecture:
//! 1. RemoteMemory: Read V8 heap objects from target process using process_vm_readv
//! 2. V8ObjectReader: Parse V8 tagged pointers and heap objects
//! 3. V8Symbolizer: Main symbolization logic coordinating object reads
//! 4. V8FrameInfo: Structured frame information for output

use std::collections::HashMap;

use crate::{error::Result, remote_memory::RemoteMemory};

use super::{
    V8Offsets, V8_FILE_TYPE_BYTECODE, V8_FILE_TYPE_MARKER, V8_FILE_TYPE_MASK,
    V8_FILE_TYPE_NATIVE_CODE, V8_FILE_TYPE_NATIVE_JSFUNC, V8_FILE_TYPE_NATIVE_SFI,
};

// V8 tagged pointer constants
const V8_SMI_TAG: u64 = 0x0;
const V8_SMI_TAG_MASK: u64 = 0x1;
const V8_SMI_TAG_SHIFT: u32 = 32;
const V8_HEAP_OBJECT_TAG: u64 = 0x1;
const V8_HEAP_OBJECT_TAG_MASK: u64 = 0x3;

// Maximum string length to read from V8 heap
const MAX_STRING_LENGTH: usize = 4096;

// Maximum position table size to read (to prevent OOM)
const MAX_POSITION_TABLE_SIZE: usize = 512 * 1024;

/// V8 frame information after symbolization.
#[derive(Debug, Clone)]
pub struct V8FrameInfo {
    pub function_name: String,
    pub file_name: String,
    pub line_number: u32,
    pub column_number: u32,
    pub frame_type: V8FrameType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V8FrameType {
    Stub,
    Bytecode,
    Baseline,
    Optimized,
    Unknown,
}

impl V8FrameInfo {
    pub fn unknown() -> Self {
        Self {
            function_name: "<unknown>".to_string(),
            file_name: "<unknown>".to_string(),
            line_number: 0,
            column_number: 0,
            frame_type: V8FrameType::Unknown,
        }
    }

    pub fn stub(marker: u64) -> Self {
        Self {
            function_name: format!("<stub:{}>", marker),
            file_name: "<native>".to_string(),
            line_number: 0,
            column_number: 0,
            frame_type: V8FrameType::Stub,
        }
    }
}

/// V8 frame metadata from eBPF (matching v8_frame_metadata_t in C)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct V8FrameMetadata {
    pub frame_type: u8,
    pub code_kind: u8,
    pub reserved: u16,
    pub code_size: u32,
    pub jsfunc_ptr: u64,
    pub sfi_ptr: u64,
    pub code_ptr: u64,
    pub pc_offset: u64,
    pub bytecode_offset: u64,
}

impl V8FrameMetadata {
    /// Extract PC offset from delta_or_marker (low 32 bits)
    pub fn extract_pc_offset(delta_or_marker: u64) -> u32 {
        (delta_or_marker & 0xFFFFFFFF) as u32
    }

    /// Extract cookie from delta_or_marker (high 32 bits)
    #[allow(dead_code)]
    pub fn extract_cookie(delta_or_marker: u64) -> u32 {
        (delta_or_marker >> 32) as u32
    }
}

/// Source position entry decoded from V8's position table.
///
/// V8 encodes source position as a 64-bit value with:
/// - bit 0: is_external flag
/// - bits 1-30: script_offset (source code position)
/// - bits 31-46: inlining_id (0 = not inlined)
#[derive(Debug, Clone, Copy)]
struct SourcePosition {
    pc_offset: u64,       // Use u64 to prevent wrapping (can exceed u32::MAX)
    source_position: u64, // Full 64-bit value including all flags and inlining_id
}

/// V8 Source Position Table Parser.
///
/// V8 encodes source position tables using variable-length encoding to save space.
/// The encoding uses delta encoding where each entry stores the difference from
/// the previous entry.
///
/// Format (variable-length encoded):
/// - PC offset delta (from previous entry)
/// - Source position delta (from previous entry)
/// - Position type (statement vs expression)
///
/// Reference: v8/src/codegen/source-position-table.cc
struct SourcePositionTable {
    entries: Vec<SourcePosition>,
}

impl SourcePositionTable {
    /// Decode a source position table from raw bytes.
    ///
    /// The table encodes delta values which are accumulated to get absolute positions.
    /// Source position is a 64-bit value encoding multiple fields (see SourcePosition struct).
    fn decode(data: &[u8]) -> Result<Self> {
        let mut entries = Vec::new();
        let mut pc_offset = -1i64;
        let mut source_position = 0i64;

        // V8 12+: ByteArray data now starts at offset 16 (FixedArray.data)
        // No additional header to skip - data starts immediately
        let mut index = 0;

        while index < data.len() {
            // Decode PC offset delta
            let (pc_delta, bytes_read) = match Self::decode_signed_varint(&data[index..]) {
                Ok(result) => result,
                Err(_) => break,
            };
            index += bytes_read;

            // Decode source position delta
            let (pos_delta, bytes_read) = match Self::decode_signed_varint(&data[index..]) {
                Ok(result) => result,
                Err(_) => break,
            };
            index += bytes_read;

            // Update cumulative PC offset
            if pc_delta >= 0 {
                pc_offset += pc_delta;
            } else {
                pc_offset -= pc_delta + 1;
            }

            // Update cumulative source position
            source_position += pos_delta;

            // Skip entries with negative pc_offset
            if pc_offset < 0 {
                continue;
            }

            entries.push(SourcePosition {
                pc_offset: pc_offset as u64,
                source_position: source_position as u64,
            });
        }

        Ok(Self { entries })
    }

    /// Find source position for a given PC offset.
    /// Uses linear search since entries are guaranteed monotonically increasing with u64.
    /// Returns the raw 64-bit source position value (including all bit fields).
    fn find_position(&self, pc_offset: u32) -> Option<u64> {
        if self.entries.is_empty() {
            return None;
        }

        let target = pc_offset as u64;

        // Linear search to find the last entry with pc_offset <= target
        let mut result = None;
        for entry in &self.entries {
            if entry.pc_offset > target {
                break;
            }
            result = Some(entry.source_position);
        }

        result
    }

    /// Decode a signed variable-length integer (zigzag encoded, 64-bit).
    /// Returns (value, bytes_consumed).
    fn decode_signed_varint(data: &[u8]) -> Result<(i64, usize)> {
        let mut result = 0u64;
        let mut shift = 0;
        let mut index = 0;

        loop {
            if index >= data.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Truncated signed varint",
                )
                .into());
            }

            let byte = data[index];
            index += 1;

            result |= ((byte & 0x7F) as u64) << shift;

            if (byte & 0x80) == 0 {
                break;
            }

            shift += 7;

            if shift >= 70 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Signed varint overflow at byte {}, shift={}", index, shift),
                )
                .into());
            }
        }

        // Zigzag decoding: (n >>> 1) ^ -(n & 1)
        let signed_value = ((result >> 1) as i64) ^ -((result & 1) as i64);

        Ok((signed_value, index)) // Return full i64 value
    }
}

/// V8 Object Reader for parsing heap objects.
pub struct V8ObjectReader<'a> {
    memory: &'a RemoteMemory,
    offsets: &'a V8Offsets,
}

impl<'a> V8ObjectReader<'a> {
    pub fn new(memory: &'a RemoteMemory, offsets: &'a V8Offsets) -> Self {
        Self { memory, offsets }
    }

    /// Verify and untag a V8 HeapObject pointer.
    fn verify_heap_object(&self, tagged_ptr: u64) -> Option<u64> {
        if tagged_ptr == 0 {
            return None;
        }
        if (tagged_ptr & V8_HEAP_OBJECT_TAG_MASK) != V8_HEAP_OBJECT_TAG {
            return None;
        }
        Some(tagged_ptr & !V8_HEAP_OBJECT_TAG_MASK)
    }

    /// Parse a V8 SMI (Small Integer) value.
    fn parse_smi(&self, tagged_value: u64) -> Option<i64> {
        if (tagged_value & V8_SMI_TAG_MASK) != V8_SMI_TAG {
            return None;
        }
        // V8 SMI: value is in upper 32 bits on 64-bit platforms
        let value = (tagged_value >> V8_SMI_TAG_SHIFT) as i32;
        Some(value as i64)
    }

    /// Read a pointer field from a V8 object.
    fn read_object_field(&self, object_addr: u64, offset: u16) -> Result<u64> {
        self.memory.read_u64(object_addr + offset as u64)
    }

    /// Read and verify a HeapObject pointer field.
    fn read_heap_object(&self, object_addr: u64, offset: u16) -> Result<Option<u64>> {
        let tagged_ptr = self.read_object_field(object_addr, offset)?;
        Ok(self.verify_heap_object(tagged_ptr))
    }

    /// Read a String object from V8 heap.
    ///
    /// V8 strings can be:
    /// - SeqString: Sequential string data (one-byte or two-byte encoding)
    /// - ConsString: Concatenation of two strings
    /// - SlicedString: Substring of another string
    /// - ThinString: Forwarding pointer to actual string
    ///
    /// This implementation handles SeqOneByteString (most common case).
    /// Two-byte strings, ConsString, and ThinString are not supported.
    pub fn read_string(&self, string_addr: u64) -> Result<String> {
        // First, read the instance_type to verify this is actually a String
        let instance_type = self.get_object_type(string_addr)?;

        // Check if it's a String type (< FirstNonstringType)
        if instance_type >= self.offsets.v8_fixed.first_nonstring_type {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Not a string: instance_type=0x{:x} >= first_nonstring_type=0x{:x}",
                    instance_type, self.offsets.v8_fixed.first_nonstring_type
                ),
            )
            .into());
        }

        // Check string representation (SeqString, ConsString, ThinString)
        let rep_type = instance_type & self.offsets.v8_fixed.string_representation_mask;

        // For now, only handle SeqString (rep_type == 0)
        if rep_type != self.offsets.v8_fixed.seq_string_tag {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("Unsupported string representation: 0x{:x} (ConsString/ThinString not implemented)", rep_type),
            ).into());
        }

        // V8 String layout (V8 11.x SeqString):
        // +0:  Map pointer (8 bytes)
        // +8:  raw_hash_field (4 bytes)
        // +12: length (int32_t, 4 bytes, NOT SMI!)
        // +16: Character data (1 or 2 bytes per char depending on encoding)

        // Read string length (uint32 at offset 12 in V8 11.x)
        let length = self.memory.read_u32(string_addr + 12)? as usize;

        if length == 0 || length > MAX_STRING_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid string length: {}", length),
            )
            .into());
        }

        // Read string data (starts at offset 16)
        let data_offset = 16u64;
        let mut buffer = vec![0u8; length];
        self.memory
            .read_at(string_addr + data_offset, &mut buffer)?;

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    /// Analyze ScopeInfo to extract function name.
    fn analyze_scope_info(&self, scope_info_addr: u64) -> Option<String> {
        const POINTER_SIZE: u64 = 8;
        const NUM_SLOTS: usize = 16;

        // Calculate data start offset (after HeapObject.map)
        let data_start = scope_info_addr + self.offsets.heap_object.map as u64 + POINTER_SIZE;

        // Read slot data (16 slots * 8 bytes = 128 bytes)
        let mut slot_data = [0u64; NUM_SLOTS];
        for (i, slot) in slot_data.iter_mut().enumerate() {
            match self.memory.read_u64(data_start + (i as u64 * POINTER_SIZE)) {
                Ok(value) => *slot = value,
                Err(_) => break,
            }
        }

        // Skip reserved slots and context locals (using ScopeInfoIndex configuration)
        let mut ndx = self.offsets.scope_info_index.first_vars as usize;

        // Decode n_context_locals (it's a SMI at the specified index)
        let n_context_locals_idx = self.offsets.scope_info_index.n_context_locals as usize;
        if n_context_locals_idx < NUM_SLOTS {
            let n_context_locals =
                self.parse_smi(slot_data[n_context_locals_idx]).unwrap_or(0) as usize;
            ndx += 2 * n_context_locals;
        }

        // Search for function name (first valid HeapObject that is a String)
        for i in ndx..NUM_SLOTS {
            let slot_value = slot_data[i];

            // Check if this is a HeapObject pointer (bit 0 = 1)
            if (slot_value & 0x1) == 0x1 {
                let obj_addr = slot_value & !0x1;

                // Try to read as string
                // This will fail for non-string types (Symbol, ScopeInfo, etc.)
                match self.read_string(obj_addr) {
                    Ok(func_name) => {
                        if !func_name.is_empty()
                            && !func_name.starts_with('<')
                            && func_name.len() <= 256
                        {
                            return Some(func_name);
                        }
                    }
                    Err(_e) => {}
                }
            }
        }

        None
    }

    /// Get the instance type of a V8 HeapObject.
    fn get_object_type(&self, object_addr: u64) -> Result<u16> {
        // Read Map pointer (at offset 0)
        let map_ptr = self.read_heap_object(object_addr, 0)?;

        if let Some(map_addr) = map_ptr {
            // Read instance_type from Map (at offset specified in vmstructs)
            let instance_type = self
                .memory
                .read_u16(map_addr + self.offsets.map.instance_type as u64)?;
            Ok(instance_type)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Failed to read Map pointer",
            )
            .into())
        }
    }

    /// Read SharedFunctionInfo object.
    ///
    /// SharedFunctionInfo contains:
    /// - Function name (either String or extracted from ScopeInfo)
    /// - Script reference
    /// - Source position information
    pub fn read_shared_function_info(&self, sfi_addr: u64) -> Result<Option<(String, u64)>> {
        // Read name_or_scope_info field
        let name_field_ptr = self.read_heap_object(
            sfi_addr,
            self.offsets.shared_function_info.name_or_scope_info,
        )?;

        let function_name = if let Some(name_ptr) = name_field_ptr {
            // Check the object type
            match self.get_object_type(name_ptr) {
                Ok(instance_type) => {
                    // Check if it's a ScopeInfo (type from vmstructs)
                    if instance_type == self.offsets.v8_type.scope_info {
                        let result = self.analyze_scope_info(name_ptr);
                        result.unwrap_or_else(|| "<anonymous>".to_string())
                    } else if instance_type < self.offsets.v8_fixed.first_nonstring_type {
                        self.read_string(name_ptr)
                            .unwrap_or_else(|_e| "<anonymous>".to_string())
                    } else {
                        "<anonymous>".to_string()
                    }
                }
                Err(_e) => "<anonymous>".to_string(),
            }
        } else {
            "<anonymous>".to_string()
        };

        // Read script_or_debug_info field
        let script_ptr = self.read_heap_object(
            sfi_addr,
            self.offsets.shared_function_info.script_or_debug_info,
        )?;

        Ok(Some((function_name, script_ptr.unwrap_or(0))))
    }

    /// Read Script object to get source file name.
    pub fn read_script(&self, script_addr: u64) -> Result<String> {
        // Read Script.name field
        let name_ptr = self.read_heap_object(script_addr, self.offsets.script.name)?;

        if let Some(name_addr) = name_ptr {
            self.read_string(name_addr)
        } else {
            Ok("<unknown>".to_string())
        }
    }

    /// Read Code object metadata for native frames.
    pub fn read_code_info(&self, code_addr: u64) -> Result<(u64, u32, u32)> {
        let instruction_start = self
            .memory
            .read_u64(code_addr + self.offsets.code.instruction_start as u64)?;

        let instruction_size = self
            .memory
            .read_u32(code_addr + self.offsets.code.instruction_size as u64)?;

        let flags = self
            .memory
            .read_u32(code_addr + self.offsets.code.flags as u64)?;

        Ok((instruction_start, instruction_size, flags))
    }

    /// Read BytecodeArray source position table.
    ///
    /// BytecodeArray contains a pointer to a ByteArray holding the position table.
    pub fn read_bytecode_position_table(&self, bytecode_addr: u64) -> Result<Vec<u8>> {
        // Read source_position_table pointer from BytecodeArray
        let table_ptr = self.read_heap_object(
            bytecode_addr,
            self.offsets.bytecode_array.source_position_table,
        )?;

        if let Some(table_addr) = table_ptr {
            self.read_byte_array(table_addr)
        } else {
            Ok(Vec::new())
        }
    }

    /// Read ByteArray data.
    ///
    /// ByteArray layout:
    /// - Map (offset 0)
    /// - Length as SMI (offset 8)
    /// - Data starts at offset 12
    fn read_byte_array(&self, array_addr: u64) -> Result<Vec<u8>> {
        // Read length field (SMI at offset 8)
        let length_field = self.memory.read_u64(array_addr + 8)?;

        let length = match self.parse_smi(length_field) {
            Some(len) if len > 0 && len < MAX_POSITION_TABLE_SIZE as i64 => len as usize,
            Some(_len) => {
                return Ok(Vec::new());
            }
            None => {
                return Ok(Vec::new());
            }
        };

        // ByteArray extends FixedArrayBase: Map(0) + Length(8) + Data(16)
        // This is consistent across V8 11 and V8 12
        let mut buffer = vec![0u8; length];
        self.memory.read_at(array_addr + 16, &mut buffer)?;

        Ok(buffer)
    }

    /// Read FixedArray (used for Code deoptimization data).
    ///
    /// FixedArray layout:
    /// - Map (offset 0)
    /// - Length as SMI (offset 8)
    /// - Elements start at offset 16, each element is 8 bytes
    fn read_fixed_array(&self, array_addr: u64) -> Result<Vec<u64>> {
        // Read length field (SMI at offset 8)
        let length_field = self.memory.read_u64(array_addr + 8)?;

        let length = match self.parse_smi(length_field) {
            Some(len) if len > 0 && len < 1024 => len as usize,
            Some(_len) => {
                return Ok(Vec::new());
            }
            None => {
                return Ok(Vec::new());
            }
        };

        // Read array elements (start at offset 16)
        let mut elements = Vec::with_capacity(length);
        for i in 0..length {
            let element = self.memory.read_u64(array_addr + 16 + (i * 8) as u64)?;
            elements.push(element);
        }

        Ok(elements)
    }

    /// Read Code object's source position table.
    pub fn read_code_position_table(&self, code_addr: u64) -> Result<Vec<u8>> {
        let position_table_ptr =
            self.read_heap_object(code_addr, self.offsets.code.source_position_table)?;

        if let Some(table_addr) = position_table_ptr {
            self.read_byte_array(table_addr)
        } else {
            Ok(Vec::new())
        }
    }

    /// Read Code object's deoptimization data and extract inlining information.
    fn read_deopt_data(&self, code_addr: u64) -> Result<Option<DeoptData>> {
        // Read deoptimization_data pointer from Code object
        let deopt_data_ptr =
            self.read_heap_object(code_addr, self.offsets.code.deoptimization_data)?;

        if deopt_data_ptr.is_none() {
            return Ok(None);
        }

        let deopt_data_addr = deopt_data_ptr.unwrap();

        // Read DeoptimizationData as FixedArray
        let deopt_array = self.read_fixed_array(deopt_data_addr)?;

        if deopt_array.is_empty() {
            return Ok(None);
        }

        // Dump first 10 elements of deopt_array to understand its structure
        let dump_count = deopt_array.len().min(10);
        for i in 0..dump_count {
            let value = deopt_array[i];
            let is_smi = (value & 0x1) == 0;
            let _is_ptr = (value & 0x1) == 1;
            if is_smi {
                let _smi_val = (value >> 32) as i32;
            } else {
            }
        }

        // Read InlinedFunctionCount (SMI at index 0)
        let num_inlined_idx = self.offsets.deopt_data_index.inlined_function_count as usize;
        if num_inlined_idx >= deopt_array.len() {
            return Ok(None);
        }

        let smi_value = deopt_array[num_inlined_idx];

        let num_inlined = match self.parse_smi(smi_value) {
            Some(n) if n > 0 => n as usize,
            Some(0) => {
                // Continue to return DeoptData with empty literal_array/inlining_positions
                // so caller can read outermost SFI from deopt_array[6]
                return Ok(Some(DeoptData {
                    num_inlined: 0,
                    literal_array: Vec::new(),
                    inlining_positions: Vec::new(),
                    deopt_array,
                }));
            }
            Some(_n) => {
                return Ok(None);
            }
            None => {
                return Ok(None);
            }
        };

        // Read LiteralArray pointer
        let literal_array_idx = self.offsets.deopt_data_index.literal_array as usize;
        if literal_array_idx >= deopt_array.len() {
            return Ok(None);
        }

        let literal_array_ptr = self.verify_heap_object(deopt_array[literal_array_idx]);
        if literal_array_ptr.is_none() {
            return Ok(None);
        }

        // Read LiteralArray (contains SFI pointers for inlined functions)
        let literal_array = self.read_fixed_array(literal_array_ptr.unwrap())?;

        // Read InliningPositions ByteArray pointer
        let inlining_pos_idx = self.offsets.deopt_data_index.inlining_positions as usize;
        if inlining_pos_idx >= deopt_array.len() {
            return Ok(None);
        }

        let inlining_pos_ptr = self.verify_heap_object(deopt_array[inlining_pos_idx]);
        if inlining_pos_ptr.is_none() {
            return Ok(None);
        }

        // Read InliningPositions ByteArray
        // Note: NO header to skip - data starts immediately with InliningPosition structures
        // Each structure is 16 bytes: position(8) + inlined_function_id(4) + padding(4)
        let inlining_positions = self.read_byte_array(inlining_pos_ptr.unwrap())?;

        Ok(Some(DeoptData {
            num_inlined,
            literal_array,
            inlining_positions,
            deopt_array,
        }))
    }
}

/// Deoptimization data extracted from Code object.
struct DeoptData {
    num_inlined: usize,
    literal_array: Vec<u64>,     // SFI pointers for inlined functions
    inlining_positions: Vec<u8>, // InliningPosition structures
    deopt_array: Vec<u64>,       // Full DeoptimizationData array (to read SFI at index 6)
}

/// V8 source position encoding (from DeoptimizationData).
/// Bits: [0]: is_external, [1-30]: script_offset, [31-46]: inlining_id
#[derive(Clone, Copy, Debug)]
struct V8SourcePosition(u64);

impl V8SourcePosition {
    fn new(value: u64) -> Self {
        V8SourcePosition(value)
    }

    /// Extract inlining_id (bits 31-46)
    fn inlining_id(&self) -> u16 {
        ((self.0 >> 31) & 0xFFFF) as u16
    }

    /// Extract script_offset (bits 1-30)
    fn script_offset(&self) -> u32 {
        ((self.0 >> 1) & 0x3FFFFFFF) as u32
    }

    /// Check if external script (bit 0)
    #[allow(dead_code)]
    fn is_external(&self) -> bool {
        (self.0 & 0x1) != 0
    }
}

/// V8 Symbolizer - Main symbolization coordinator.
pub struct V8Symbolizer {
    memory: RemoteMemory,
    offsets: V8Offsets,
    script_cache: HashMap<u64, String>,
}

impl V8Symbolizer {
    pub fn new(pid: u32, offsets: V8Offsets) -> Self {
        Self {
            memory: RemoteMemory::new(pid),
            offsets,
            script_cache: HashMap::new(),
        }
    }

    /// Symbolize a V8 frame using metadata from eBPF.
    pub fn symbolize_frame(&mut self, metadata: &V8FrameMetadata) -> V8FrameInfo {
        // Use if-else instead of match to avoid Rust pattern binding issues
        // Cast u8 to u64 for comparison
        let frame_type = metadata.frame_type as u64;

        if frame_type == V8_FILE_TYPE_MARKER {
            V8FrameInfo::stub(metadata.bytecode_offset)
        } else if frame_type == V8_FILE_TYPE_BYTECODE {
            self.symbolize_bytecode_frame(metadata)
        } else if frame_type == V8_FILE_TYPE_NATIVE_JSFUNC
            || frame_type == V8_FILE_TYPE_NATIVE_CODE
            || frame_type == V8_FILE_TYPE_NATIVE_SFI
        {
            self.symbolize_native_frame(metadata)
        } else {
            V8FrameInfo::unknown()
        }
    }

    /// Symbolize a bytecode (interpreted) frame.
    fn symbolize_bytecode_frame(&mut self, metadata: &V8FrameMetadata) -> V8FrameInfo {
        // Read SharedFunctionInfo from JSFunction
        if metadata.jsfunc_ptr == 0 {
            return V8FrameInfo::unknown();
        }

        let (function_name, script_addr, line_number) = {
            let reader = V8ObjectReader::new(&self.memory, &self.offsets);

            let sfi_result =
                reader.read_heap_object(metadata.jsfunc_ptr, self.offsets.js_function.shared);

            let sfi_addr = match sfi_result {
                Ok(Some(addr)) => addr,
                _ => return V8FrameInfo::unknown(),
            };

            // Read function name and script from SFI
            let (fname, saddr) = reader
                .read_shared_function_info(sfi_addr)
                .unwrap_or(None)
                .unwrap_or(("<unknown>".to_string(), 0));

            // Try to get line number from bytecode position table
            let lnum = if metadata.bytecode_offset > 0 {
                // Read BytecodeArray from SharedFunctionInfo
                if let Ok(Some(bytecode_addr)) = reader
                    .read_heap_object(sfi_addr, self.offsets.shared_function_info.function_data)
                {
                    // Read and parse position table
                    if let Ok(table_data) = reader.read_bytecode_position_table(bytecode_addr) {
                        if let Ok(pos_table) = SourcePositionTable::decode(&table_data) {
                            // Find source position for bytecode offset
                            if let Some(source_pos) =
                                pos_table.find_position(metadata.bytecode_offset as u32)
                            {
                                // Extract script offset from source position (bits 1-30)
                                // This is 0-indexed character offset in source
                                let script_offset = ((source_pos >> 1) & ((1 << 30) - 1)) as u32;
                                script_offset
                            } else {
                                0
                            }
                        } else {
                            0
                        }
                    } else {
                        0
                    }
                } else {
                    0
                }
            } else {
                0
            };

            (fname, saddr, lnum)
        };

        // Read file name from Script (with caching) - now reader is dropped
        let file_name = if script_addr != 0 {
            self.get_script_name(script_addr)
        } else {
            "<unknown>".to_string()
        };

        V8FrameInfo {
            function_name,
            file_name,
            line_number,
            column_number: 0,
            frame_type: V8FrameType::Bytecode,
        }
    }

    /// Symbolize a native (compiled) frame with inlining support.
    fn symbolize_native_frame(&mut self, metadata: &V8FrameMetadata) -> V8FrameInfo {
        // Try to expand inlined frames if we have Code object and PC offset
        if metadata.code_ptr != 0 && metadata.pc_offset != 0 {
            if let Ok(inlined_frames) =
                self.expand_inlined_frames(metadata.code_ptr, metadata.pc_offset, metadata.sfi_ptr)
            {
                if !inlined_frames.is_empty() {
                    // Return the innermost inlined frame
                    // TODO: Modify API to return Vec<V8FrameInfo> to show full inline chain
                    return inlined_frames[0].clone();
                }
            }
        }

        // Fallback to regular symbolization without inlining
        let (function_name, script_addr) = {
            let reader = V8ObjectReader::new(&self.memory, &self.offsets);

            // Read SharedFunctionInfo
            let sfi_addr = if metadata.sfi_ptr != 0 {
                metadata.sfi_ptr
            } else if metadata.jsfunc_ptr != 0 {
                // Try to get SFI from JSFunction
                match reader.read_heap_object(metadata.jsfunc_ptr, self.offsets.js_function.shared)
                {
                    Ok(Some(addr)) => addr,
                    _ => return V8FrameInfo::unknown(),
                }
            } else {
                return V8FrameInfo::unknown();
            };

            // Read function name and script
            reader
                .read_shared_function_info(sfi_addr)
                .unwrap_or(None)
                .unwrap_or(("<unknown>".to_string(), 0))
        };

        // Read file name from Script (now reader is dropped)
        let file_name = if script_addr != 0 {
            self.get_script_name(script_addr)
        } else {
            "<unknown>".to_string()
        };

        let frame_type_u64 = metadata.frame_type as u64;
        let frame_type = if frame_type_u64 == V8_FILE_TYPE_NATIVE_JSFUNC {
            V8FrameType::Baseline
        } else if frame_type_u64 == V8_FILE_TYPE_NATIVE_CODE {
            V8FrameType::Optimized
        } else {
            V8FrameType::Unknown
        };

        V8FrameInfo {
            function_name,
            file_name,
            line_number: 0,
            column_number: 0,
            frame_type,
        }
    }

    /// Expand inlined function frames from optimized Code object.
    ///
    /// Returns frames from innermost (first inlined) to outermost (calling function).
    fn expand_inlined_frames(
        &self,
        code_addr: u64,
        pc_offset: u64,
        _sfi_addr: u64,
    ) -> Result<Vec<V8FrameInfo>> {
        let reader = V8ObjectReader::new(&self.memory, &self.offsets);
        let mut frames = Vec::new();

        // Remove HeapObject tag to get actual object address
        let untagged_code_addr = code_addr & !V8_HEAP_OBJECT_TAG_MASK;

        // Read deoptimization data
        let deopt_data = match reader.read_deopt_data(untagged_code_addr) {
            Ok(Some(data)) => data,
            Ok(None) => {
                return Ok(frames);
            }
            Err(_e) => {
                return Ok(frames);
            }
        };

        if deopt_data.num_inlined == 0 {
            // Even without inline frames, read the outermost function from deopt_array[6]
            let outermost_sfi_idx = self.offsets.deopt_data_index.shared_function_info as usize;

            if outermost_sfi_idx < deopt_data.deopt_array.len() {
                let sfi_ptr_raw = deopt_data.deopt_array[outermost_sfi_idx];

                if sfi_ptr_raw != 0 && (sfi_ptr_raw & 0x1) == 0x1 {
                    let sfi_addr = sfi_ptr_raw & !0x1;

                    match reader.read_shared_function_info(sfi_addr) {
                        Ok(Some((func_name, script_addr))) => {
                            let file_name = if script_addr != 0 {
                                reader
                                    .read_script(script_addr)
                                    .unwrap_or_else(|_| "<unknown>".to_string())
                            } else {
                                "<unknown>".to_string()
                            };

                            frames.push(V8FrameInfo {
                                function_name: func_name.clone(),
                                file_name: file_name.clone(),
                                line_number: pc_offset as u32,
                                column_number: 0,
                                frame_type: V8FrameType::Optimized,
                            });
                            return Ok(frames);
                        }
                        _ => {}
                    }
                }
            }

            return Ok(frames);
        }

        // Read source position table
        let position_table_data = match reader.read_code_position_table(untagged_code_addr) {
            Ok(data) => data,
            Err(_e) => {
                return Ok(frames);
            }
        };

        if position_table_data.is_empty() {
            return Ok(frames);
        }

        // Decode position table to find source position for PC offset
        let pos_table = match SourcePositionTable::decode(&position_table_data) {
            Ok(table) => table,
            Err(_e) => {
                return Ok(frames);
            }
        };

        let source_pos_value = match pos_table.find_position(pc_offset as u32) {
            Some(pos) => pos,
            None => {
                if !pos_table.entries.is_empty() {}
                return Ok(frames);
            }
        };

        // Parse source position (source_pos_value is already u64)
        let mut source_pos = V8SourcePosition::new(source_pos_value);

        // Check if source_position is a negative/special value
        // V8 uses negative values (e.g., -1 = kNoSourcePosition, -2 = other special states)
        // When converted to u64, negative values become very large numbers
        // This causes invalid inlining_id extraction (e.g., 65535 from -2)
        let source_pos_i64 = source_pos.0 as i64;
        if source_pos_i64 < 0 {
            // Return empty frames - the caller will add a generic frame
            return Ok(frames);
        }

        // Expand inlining chain (from innermost to outermost)
        let mut _iteration = 0;
        while source_pos.inlining_id() != 0 {
            _iteration += 1;
            let inlining_id = source_pos.inlining_id();

            // InliningPosition struct size: 16 bytes
            // Layout: position (8 bytes) + inlined_function_id (4 bytes) + padding (4 bytes)
            let item_offset = ((inlining_id - 1) * 16) as usize;

            if item_offset + 16 > deopt_data.inlining_positions.len() {
                log::warn!(
                    "[V8] InliningPosition out of bounds: id={}, offset={}, len={}",
                    inlining_id,
                    item_offset,
                    deopt_data.inlining_positions.len()
                );
                break;
            }

            // Read inlined_function_id (int32 at offset +8)
            let func_id_bytes: [u8; 4] = deopt_data.inlining_positions
                [item_offset + 8..item_offset + 12]
                .try_into()
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid function ID")
                })?;
            let func_id = i32::from_le_bytes(func_id_bytes);

            // Get inlined function's SFI
            let inlined_sfi_addr = if func_id >= 0 {
                let sfi_idx = func_id as usize;
                if sfi_idx >= deopt_data.literal_array.len() {
                    log::warn!(
                        "[V8] SFI index out of bounds: func_id={}, idx={}, len={}",
                        func_id,
                        sfi_idx,
                        deopt_data.literal_array.len()
                    );
                    break;
                }
                let sfi_addr = deopt_data.literal_array[sfi_idx];

                sfi_addr
            } else {
                // func_id == -1: Skip this inlined frame
                let pos_bytes: [u8; 8] = deopt_data.inlining_positions
                    [item_offset..item_offset + 8]
                    .try_into()
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid position")
                    })?;
                source_pos = V8SourcePosition::new(u64::from_le_bytes(pos_bytes));
                continue;
            };

            // Verify it's a valid HeapObject pointer
            let inlined_sfi_ptr = if (inlined_sfi_addr & 0x1) == 0x1 {
                let untagged = inlined_sfi_addr & !0x1;
                untagged
            } else {
                log::warn!(
                    "[V8] Invalid SFI pointer (not tagged): 0x{:x}",
                    inlined_sfi_addr
                );
                break;
            };

            // Read inlined function info
            let (func_name, script_addr) = match reader.read_shared_function_info(inlined_sfi_ptr) {
                Ok(Some((name, script))) => (name, script),
                Ok(None) => ("<unknown-inlined>".to_string(), 0),
                Err(_e) => ("<unknown-inlined>".to_string(), 0),
            };

            let file_name = if script_addr != 0 {
                // Need to access script_cache, but we can't call self method here
                // For now, read directly without caching
                match reader.read_script(script_addr) {
                    Ok(name) => name,
                    Err(_e) => "<unknown>".to_string(),
                }
            } else {
                "<unknown>".to_string()
            };

            // Create frame for this inlined function
            frames.push(V8FrameInfo {
                function_name: func_name.clone(),
                file_name: file_name.clone(),
                line_number: source_pos.script_offset(), // Simplified: use script_offset as line
                column_number: 0,
                frame_type: V8FrameType::Optimized,
            });

            // Read next source position (uint64 at offset +0)
            let pos_bytes: [u8; 8] = deopt_data.inlining_positions[item_offset..item_offset + 8]
                .try_into()
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid position")
                })?;
            let new_source_pos = V8SourcePosition::new(u64::from_le_bytes(pos_bytes));

            // Verify monotonic decrease
            if new_source_pos.inlining_id() >= inlining_id {
                log::warn!(
                    "[V8] Inlining ID not monotonically decreasing: {} -> {}",
                    inlining_id,
                    new_source_pos.inlining_id()
                );
                break;
            }

            source_pos = new_source_pos;
        }

        // After the inline chain, generate the outermost frame (inlining_id=0)
        // This is the actual function that contains all the inlined functions

        // Read the outermost SFI from DeoptimizationData[SharedFunctionInfo] index
        let outermost_sfi_idx = self.offsets.deopt_data_index.shared_function_info as usize;

        if outermost_sfi_idx < deopt_data.deopt_array.len() {
            let sfi_ptr_raw = deopt_data.deopt_array[outermost_sfi_idx];

            // Verify it's a valid HeapObject pointer (bit 0 = 1)
            if sfi_ptr_raw != 0 && (sfi_ptr_raw & 0x1) == 0x1 {
                let sfi_addr = sfi_ptr_raw & !0x1;

                match reader.read_shared_function_info(sfi_addr) {
                    Ok(Some((func_name, script_addr))) => {
                        let file_name = if script_addr != 0 {
                            match reader.read_script(script_addr) {
                                Ok(name) => name,
                                Err(_e) => "<unknown>".to_string(),
                            }
                        } else {
                            "<unknown>".to_string()
                        };

                        frames.push(V8FrameInfo {
                            function_name: func_name.clone(),
                            file_name: file_name.clone(),
                            line_number: source_pos.script_offset(),
                            column_number: 0,
                            frame_type: V8FrameType::Optimized,
                        });
                    }
                    Ok(None) => {}
                    Err(_e) => {}
                }
            } else {
            }
        } else {
        }

        // Reverse frames to get caller-to-callee order (outermost to innermost)
        // Currently frames are in innermost-to-outermost order from the loop
        frames.reverse();

        Ok(frames)
    }

    /// Get script file name with caching.
    fn get_script_name(&mut self, script_addr: u64) -> String {
        if let Some(cached) = self.script_cache.get(&script_addr) {
            return cached.clone();
        }

        let reader = V8ObjectReader::new(&self.memory, &self.offsets);
        let file_name = reader
            .read_script(script_addr)
            .unwrap_or_else(|_| "<unknown>".to_string());

        self.script_cache.insert(script_addr, file_name.clone());
        file_name
    }
}

/// Escape JavaScript built-in method names that conflict with Grafana parsing.
///
/// Grafana's flame graph uses JavaScript to parse symbol names. When a symbol
/// matches Object.prototype methods like "toString", Grafana's code does
/// obj["toString"] which returns the built-in function instead of undefined,
/// causing "b[m.getLabel(...)].push is not a function" errors.
///
/// Solution: Append "[JS]" to reserved names to make them distinct.
fn escape_js_reserved_name(name: String) -> String {
    // Handle multi-frame symbols separated by semicolons (inlined functions)
    // Each frame should get the [JS] suffix individually
    if name.contains(';') {
        name.split(';')
            .map(|frame| format!("{} [JS]", frame.trim()))
            .collect::<Vec<_>>()
            .join(";")
    } else {
        format!("{} [JS]", name)
    }
}

/// C FFI function to resolve a V8 frame using OpenTelemetry encoding format
/// Returns a C-allocated string that must be freed by the caller using clib_mem_free()
///
/// Parameters:
/// - pointer_and_type: Lower 3 bits = frame type, rest = pointer value
/// - delta_or_marker: Bytecode offset, source position, or stub marker
/// - sfi_fallback: SharedFunctionInfo pointer for fallback (from eBPF extra_data_b)
#[no_mangle]
pub unsafe extern "C" fn resolve_v8_frame(
    pid: u32,
    pointer_and_type: u64,
    delta_or_marker: u64,
    sfi_fallback: u64,
) -> *mut std::os::raw::c_char {
    use super::get_offsets_for_pid;
    use crate::remote_memory::RemoteMemory;
    use log::error;
    use std::ffi::CString;
    use std::os::raw::c_char;

    // Extract frame type and pointer from OpenTelemetry encoding (lower 3 bits)
    let frame_type = pointer_and_type & V8_FILE_TYPE_MASK;
    let pointer = pointer_and_type & !V8_FILE_TYPE_MASK;

    // Get V8 offsets for this process (fast HashMap lookup)
    let v8_offsets = get_offsets_for_pid(pid);
    let mem = RemoteMemory::new(pid);

    // Symbolize based on frame type - use complete symbolization logic
    let symbol = match frame_type {
        V8_FILE_TYPE_MARKER => {
            // Stub/Marker frame - use delta_or_marker as the frame marker value
            symbolize_stub_frame(delta_or_marker, &v8_offsets.frame_types)
        }
        V8_FILE_TYPE_BYTECODE | V8_FILE_TYPE_NATIVE_SFI => {
            // Bytecode or Native SFI frame - pointer is SharedFunctionInfo
            // Read SFI from process memory and extract function name
            symbolize_sfi_frame(&mem, pointer, v8_offsets, frame_type)
        }
        V8_FILE_TYPE_NATIVE_JSFUNC => {
            // Baseline frame - pointer is JSFunction
            symbolize_baseline_frame(&mem, pointer, v8_offsets)
        }
        V8_FILE_TYPE_NATIVE_CODE => {
            // Optimized native code frame - pointer is Code object
            symbolize_native_code_frame(
                pid,
                &mem,
                pointer,
                delta_or_marker,
                sfi_fallback,
                v8_offsets,
            )
        }
        _ => {
            // Unknown frame type
            format!("<unknown-frame-type-0x{:x}>", frame_type)
        }
    };

    // Escape JavaScript reserved names to prevent Grafana parsing errors
    let symbol = escape_js_reserved_name(symbol);

    // Remove null bytes from symbol string (V8 may return strings with embedded nulls)
    let symbol = symbol.replace('\0', "");

    // Allocate and return C string
    match CString::new(symbol) {
        Ok(c_str) => {
            let bytes = c_str.as_bytes_with_nul();
            let len = bytes.len();

            extern "C" {
                fn clib_mem_alloc_aligned(
                    name: *const c_char,
                    size: usize,
                    align: u32,
                    alloc_sz: *mut usize,
                ) -> *mut std::ffi::c_void;
            }

            let tag = b"v8_symbol\0".as_ptr() as *const c_char;
            let mut alloc_sz: usize = 0;
            let ptr =
                clib_mem_alloc_aligned(tag, len, 0, &mut alloc_sz as *mut usize) as *mut c_char;

            if !ptr.is_null() {
                std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, ptr, len);
                ptr
            } else {
                error!("[V8] Failed to allocate memory for symbol");
                std::ptr::null_mut()
            }
        }
        Err(_e) => {
            error!("[V8] Failed to create CString: {:?}", _e);
            std::ptr::null_mut()
        }
    }
}

/// Symbolize a Stub/Marker frame using version-specific frame type values
/// These are V8 internal frames (entry, exit, builtin, etc.)
fn symbolize_stub_frame(
    marker_value: u64,
    frame_types: &crate::unwind::v8::V8FrameTypes,
) -> String {
    // Use version-specific frame type values from V8 vmstructs
    // Check marker_value != 0 to avoid matching unset fields
    let frame_name = if marker_value == frame_types.entry_frame as u64 {
        "V8:EntryFrame"
    } else if marker_value == frame_types.construct_entry_frame as u64 {
        "V8:ConstructEntryFrame"
    } else if marker_value == frame_types.exit_frame as u64 {
        "V8:ExitFrame"
    } else if marker_value != 0 && marker_value == frame_types.wasm_frame as u64 {
        "V8:WasmFrame"
    } else if marker_value != 0 && marker_value == frame_types.wasm_to_js_frame as u64 {
        "V8:WasmToJsFrame"
    } else if marker_value != 0 && marker_value == frame_types.wasm_to_js_function_frame as u64 {
        "V8:WasmToJsFunctionFrame"
    } else if marker_value != 0 && marker_value == frame_types.js_to_wasm_frame as u64 {
        "V8:JsToWasmFrame"
    } else if marker_value != 0 && marker_value == frame_types.wasm_debug_break_frame as u64 {
        "V8:WasmDebugBreakFrame"
    } else if marker_value != 0 && marker_value == frame_types.stack_switch_frame as u64 {
        "V8:StackSwitchFrame"
    } else if marker_value != 0 && marker_value == frame_types.wasm_exit_frame as u64 {
        "V8:WasmExitFrame"
    } else if marker_value != 0 && marker_value == frame_types.c_wasm_entry_frame as u64 {
        "V8:CWasmEntryFrame"
    } else if marker_value != 0 && marker_value == frame_types.wasm_compile_lazy_frame as u64 {
        "V8:WasmCompileLazyFrame"
    } else if marker_value != 0 && marker_value == frame_types.wasm_liftoff_setup_frame as u64 {
        "V8:WasmLiftoffSetupFrame"
    } else if marker_value == frame_types.interpreted_frame as u64 {
        "V8:InterpretedFrame"
    } else if marker_value == frame_types.baseline_frame as u64 {
        "V8:BaselineFrame"
    } else if marker_value != 0 && marker_value == frame_types.maglev_frame as u64 {
        "V8:MaglevFrame"
    } else if marker_value != 0 && marker_value == frame_types.turbofan_frame as u64 {
        "V8:TurbofanFrame"
    } else if marker_value != 0 && marker_value == frame_types.optimized_frame as u64 {
        "V8:OptimizedFrame" // V8 9-10 only
    } else if marker_value == frame_types.stub_frame as u64 {
        "V8:StubFrame"
    } else if marker_value != 0
        && marker_value == frame_types.turbofan_stub_with_context_frame as u64
    {
        "V8:TurbofanStubWithContextFrame"
    } else if marker_value == frame_types.builtin_continuation_frame as u64 {
        "V8:BuiltinContinuationFrame"
    } else if marker_value == frame_types.js_builtin_continuation_frame as u64 {
        "V8:JavaScriptBuiltinContinuationFrame"
    } else if marker_value == frame_types.js_builtin_continuation_with_catch_frame as u64 {
        "V8:JavaScriptBuiltinContinuationWithCatchFrame"
    } else if marker_value == frame_types.internal_frame as u64 {
        "V8:InternalFrame"
    } else if marker_value == frame_types.construct_frame as u64 {
        "V8:ConstructFrame"
    } else if marker_value != 0 && marker_value == frame_types.fast_construct_frame as u64 {
        "V8:FastConstructFrame"
    } else if marker_value == frame_types.builtin_frame as u64 {
        "V8:BuiltinFrame"
    } else if marker_value == frame_types.builtin_exit_frame as u64 {
        "V8:BuiltinExitFrame"
    } else if marker_value == frame_types.native_frame as u64 {
        "V8:NativeFrame"
    } else if marker_value != 0 && marker_value == frame_types.api_callback_exit_frame as u64 {
        "V8:ApiCallbackExitFrame"
    } else if marker_value != 0 && marker_value == frame_types.irregexp_frame as u64 {
        "V8:IrregexpFrame"
    } else {
        return format!("V8:UnknownStub#{}", marker_value);
    };

    frame_name.to_string()
}

/// Symbolize a Bytecode or Native SFI frame
/// pointer is SharedFunctionInfo address (already untagged)
fn symbolize_sfi_frame(
    mem: &RemoteMemory,
    sfi_ptr: u64,
    offsets: &V8Offsets,
    _frame_type: u64,
) -> String {
    use log::warn;

    // SFI pointer should be HeapObject (bit 0 = 1)
    let sfi_addr = sfi_ptr | 0x1;

    if !is_heap_object(sfi_addr) {
        return format!("<invalid-sfi@0x{:x}>", sfi_ptr);
    }

    // Read function name from SFI.name_or_scope_info
    let name_or_scope_addr =
        match mem.read_u64(sfi_ptr + offsets.shared_function_info.name_or_scope_info as u64) {
            Ok(addr) => addr,
            Err(_e) => {
                warn!("[V8] Failed to read SFI.name_or_scope_info: {:?}", _e);
                return format!("<read-error@0x{:x}>", sfi_ptr);
            }
        };

    let func_name = extract_function_name(mem, name_or_scope_addr, sfi_ptr, offsets);

    format!("{}", func_name)
}

/// Symbolize a Baseline compiled frame
/// pointer is JSFunction address (already untagged)
fn symbolize_baseline_frame(mem: &RemoteMemory, jsfunc_ptr: u64, offsets: &V8Offsets) -> String {
    use log::warn;

    let jsfunc_addr = jsfunc_ptr | 0x1; // Add HeapObject tag

    if !is_heap_object(jsfunc_addr) {
        return format!("<invalid-jsfunc@0x{:x}>", jsfunc_ptr);
    }

    // Read SharedFunctionInfo from JSFunction
    let sfi_addr = match mem.read_u64(jsfunc_ptr + offsets.js_function.shared as u64) {
        Ok(addr) => addr,
        Err(_e) => {
            warn!("[V8] Failed to read JSFunction.shared: {:?}", _e);
            return format!("<baseline-read-error@0x{:x}>", jsfunc_ptr);
        }
    };

    if !is_heap_object(sfi_addr) {
        return format!("<baseline-invalid-sfi@0x{:x}>", jsfunc_ptr);
    }

    let sfi_ptr = sfi_addr & !0x1;

    // Read function name from SFI
    let name_or_scope_addr =
        match mem.read_u64(sfi_ptr + offsets.shared_function_info.name_or_scope_info as u64) {
            Ok(addr) => addr,
            Err(_) => return format!("<baseline-name-error@0x{:x}>", jsfunc_ptr),
        };

    let func_name = extract_function_name(mem, name_or_scope_addr, sfi_ptr, offsets);
    format!("{}", func_name)
}

/// Symbolize an Optimized native code frame
/// pointer is Code object address (already untagged)
/// sfi_fallback is SharedFunctionInfo pointer from eBPF (for fallback when Code has no DeoptData)
fn symbolize_native_code_frame(
    pid: u32,
    mem: &RemoteMemory,
    code_ptr: u64,
    delta_or_marker: u64,
    sfi_fallback: u64,
    offsets: &V8Offsets,
) -> String {
    let code_addr = code_ptr | 0x1; // Add HeapObject tag

    if !is_heap_object(code_addr) {
        return format!("<invalid-code@0x{:x}>", code_ptr);
    }

    // Extract PC offset from delta_or_marker (low 32 bits)
    let pc_offset = (delta_or_marker & 0xFFFFFFFF) as u64;

    // Try to expand inlined frames if we have PC offset
    if pc_offset != 0 {
        let symbolizer = V8Symbolizer::new(pid, *offsets);

        // Try to expand inline frames
        if let Ok(inlined_frames) = symbolizer.expand_inlined_frames(code_addr, pc_offset, 0) {
            if !inlined_frames.is_empty() {
                // Return all inlined frames from outermost to innermost (caller to callee)
                // Format: "outermost;...;next;innermost"
                // Frames are already in correct order from expand_inlined_frames
                let frame_names: Vec<String> = inlined_frames
                    .iter()
                    .map(|f| f.function_name.clone())
                    .collect();

                return format!("{}", frame_names.join(";"));
            }
        }
    }

    // Fallback: Try to get function name from SFI
    // Note: sfi_fallback is already untagged by eBPF (v8_read_object_ptr removes tag)
    // read_shared_function_info expects untagged address
    if sfi_fallback != 0 {
        let reader = V8ObjectReader::new(mem, offsets);
        match reader.read_shared_function_info(sfi_fallback) {
            Ok(Some((func_name, _script_addr))) => {
                return format!("{}", func_name);
            }
            _ => {}
        }
    }

    // Final fallback: For Code objects without inline info or valid SFI, show address
    format!("<optimized-code@0x{:x}>", code_ptr)
}

/// Extract function name from name_or_scope_info field
/// This can be either a String or ScopeInfo object
fn extract_function_name(
    mem: &RemoteMemory,
    name_or_scope_addr: u64,
    sfi_ptr: u64,
    offsets: &V8Offsets,
) -> String {
    use log::warn;

    if name_or_scope_addr == 0 {
        return format!("<anonymous@0x{:x}>", sfi_ptr);
    }

    if !is_heap_object(name_or_scope_addr) {
        return format!("<unnamed@0x{:x}>", sfi_ptr);
    }

    let name_or_scope_ptr = name_or_scope_addr & !0x1;

    // Read the object's instance type
    match read_object_type(mem, name_or_scope_addr, offsets) {
        Ok(instance_type) => {
            // Check if it's a ScopeInfo
            if instance_type == offsets.v8_type.scope_info {
                match analyze_scope_info(mem, name_or_scope_ptr, offsets) {
                    Ok(Some(name)) => {
                        return name;
                    }
                    Ok(None) => {
                        // Try script name as fallback
                        if let Ok(script_name) = read_script_name(mem, sfi_ptr, offsets) {
                            return format!("<{}:anonymous>", script_name);
                        }
                        return format!("<anonymous@0x{:x}>", sfi_ptr);
                    }
                    Err(_e) => {
                        warn!("[V8] ScopeInfo analysis failed: {:?}", _e);
                        return format!("<scope-error@0x{:x}>", sfi_ptr);
                    }
                }
            } else if instance_type < offsets.v8_fixed.first_nonstring_type {
                // It's a String type
                match read_v8_string(mem, name_or_scope_ptr, offsets) {
                    Ok(name) if !name.is_empty() => {
                        return name;
                    }
                    Ok(_) => return format!("<empty@0x{:x}>", sfi_ptr),
                    Err(_e) => {
                        warn!("[V8] String read failed: {:?}", _e);
                        return format!("<string-error@0x{:x}>", sfi_ptr);
                    }
                }
            } else {
                return format!("<unknown-type-{}@0x{:x}>", instance_type, sfi_ptr);
            }
        }
        Err(_e) => {
            warn!("[V8] Failed to read object type");
            return format!("<type-error@0x{:x}>", sfi_ptr);
        }
    }
}

// ============================================================================
// V8 Helper Functions
// ============================================================================

/// Decode V8 Small Integer (SMI) value.
/// V8 SMI encoding: value is shifted left by 32 bits and tagged with bit 0 = 0
#[inline]
fn decode_smi(tagged_value: u64) -> i64 {
    // Check if it's actually a SMI (bit 0 should be 0)
    if (tagged_value & V8_SMI_TAG_MASK) != V8_SMI_TAG {
        return 0;
    }

    // Arithmetic shift right to decode (sign-extended)
    (tagged_value as i64) >> V8_SMI_TAG_SHIFT
}

/// Check if a value is a HeapObject pointer
#[inline]
fn is_heap_object(value: u64) -> bool {
    (value & V8_HEAP_OBJECT_TAG_MASK) == V8_HEAP_OBJECT_TAG
}

/// Read the instance type of a V8 HeapObject.
///
/// This reads the Map object and extracts the instance_type field,
/// which tells us what kind of object this is (JSFunction, ScopeInfo, String, etc.)
fn read_object_type(mem: &RemoteMemory, obj_addr: u64, offsets: &V8Offsets) -> Result<u16> {
    // Remove tag to get actual address
    let obj_ptr = obj_addr & !V8_HEAP_OBJECT_TAG_MASK;

    // Read HeapObject.map at offset 0
    let map_addr = mem.read_u64(obj_ptr + offsets.heap_object.map as u64)?;
    let map_ptr = map_addr & !V8_HEAP_OBJECT_TAG_MASK;

    // Read Map.instance_type
    let instance_type = mem.read_u16(map_ptr + offsets.map.instance_type as u64)?;

    Ok(instance_type)
}

/// Analyze V8 ScopeInfo object to extract function name.
///
/// ScopeInfo has a complex layout that varies between V8 versions.
/// We use a heuristic approach:
/// - Skip reserved slots and context locals
/// - Scan remaining slots for first valid string (assumed to be function name)
fn analyze_scope_info(
    mem: &RemoteMemory,
    scope_info_addr: u64,
    offsets: &V8Offsets,
) -> Result<Option<String>> {
    const POINTER_SIZE: u64 = 8;
    const NUM_SLOTS: usize = 16;

    // Calculate data start offset
    // ScopeInfo is a HeapObject, so data starts after the Map pointer
    let data_start = scope_info_addr + offsets.heap_object.map as u64 + POINTER_SIZE;

    // Read slot data (16 slots * 8 bytes = 128 bytes)
    let mut slot_data = [0u64; NUM_SLOTS];
    for (i, slot) in slot_data.iter_mut().enumerate() {
        match mem.read_u64(data_start + (i as u64 * POINTER_SIZE)) {
            Ok(value) => *slot = value,
            Err(_) => break, // Stop on read error
        }
    }

    // Skip reserved slots and context locals
    let mut ndx = offsets.scope_info_index.first_vars as usize;

    // Decode n_context_locals (it's a SMI at the specified index)
    let n_context_locals_idx = offsets.scope_info_index.n_context_locals as usize;
    if n_context_locals_idx < NUM_SLOTS {
        let n_context_locals = decode_smi(slot_data[n_context_locals_idx]) as usize;
        ndx += 2 * n_context_locals;
    }

    // Search for function name (first valid HeapObject that looks like a string)
    for i in ndx..NUM_SLOTS {
        let slot_value = slot_data[i];

        if is_heap_object(slot_value) {
            // Try to read this as a String
            if let Ok(func_name) =
                read_v8_string(mem, slot_value & !V8_HEAP_OBJECT_TAG_MASK, offsets)
            {
                if !func_name.is_empty() {
                    return Ok(Some(func_name));
                }
            }
        }
    }

    Ok(None)
}

/// Read a V8 String object from memory.
///
/// V8 has multiple string types (SeqOneByteString, SeqTwoByteString, etc.)
/// This is a simplified implementation that handles the most common case.
fn read_v8_string(mem: &RemoteMemory, string_addr: u64, _offsets: &V8Offsets) -> Result<String> {
    // V8 String layout (V8 11.x):
    // +0:  Map pointer (8 bytes)
    // +8:  raw_hash_field (4 bytes)
    // +12: length (int32_t, 4 bytes, NOT SMI!)
    // +16: Character data

    const STRING_DATA_OFFSET: u64 = 16;
    const MAX_STRING_LEN: usize = 1024;

    // Read length as int32_t at offset 12
    let length = mem.read_u32(string_addr + 12)? as usize;

    if length == 0 || length > MAX_STRING_LEN {
        return Ok(String::new());
    }

    // Read string data starting at offset 16
    let mut buffer = vec![0u8; length];
    if mem
        .read_at(string_addr + STRING_DATA_OFFSET, &mut buffer)
        .is_ok()
    {
        // Try to convert to UTF-8 string
        String::from_utf8(buffer).or_else(|_| Ok(String::new()))
    } else {
        Ok(String::new())
    }
}

/// Read script name from SharedFunctionInfo.
///
/// This reads the script_or_debug_info field and extracts the script's name.
fn read_script_name(mem: &RemoteMemory, sfi_ptr: u64, offsets: &V8Offsets) -> Result<String> {
    // Read SharedFunctionInfo.script_or_debug_info at offset +32
    let script_addr =
        mem.read_u64(sfi_ptr + offsets.shared_function_info.script_or_debug_info as u64)?;

    if !is_heap_object(script_addr) {
        return Ok(String::from("unknown"));
    }

    let script_ptr = script_addr & !V8_HEAP_OBJECT_TAG_MASK;

    // Read Script.name at offset (varies by version, using 16 for V8 11.x)
    let name_addr = mem.read_u64(script_ptr + offsets.script.name as u64)?;

    if !is_heap_object(name_addr) {
        return Ok(String::from("unknown"));
    }

    let name_ptr = name_addr & !V8_HEAP_OBJECT_TAG_MASK;

    // Read the script name string
    read_v8_string(mem, name_ptr, offsets)
}

#[cfg(test)]
mod tests;
