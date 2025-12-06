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

use std::{
    cell::OnceCell,
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use libc::c_void;
use log::{trace, warn};
use object::{Object, ObjectSection, ObjectSymbol};
use regex::Regex;
use semver::{Version, VersionReq};

use crate::{
    error::{Error, Result},
    maps::{get_memory_mappings, MemoryArea},
    utils::{bpf_delete_elem, bpf_update_elem, get_errno, BPF_ANY},
};

use super::elf_utils::MappedFile;

// V8 submodules
pub mod symbolizer;

use symbolizer::{V8FrameMetadata, V8Symbolizer};

// V8 Frame type constants
// Public constants for reuse in v8_symbolizer module
pub const V8_FILE_TYPE_MASK: u64 = 0x7;
pub const V8_FILE_TYPE_MARKER: u64 = 0x0;
pub const V8_FILE_TYPE_BYTECODE: u64 = 0x1;
pub const V8_FILE_TYPE_NATIVE_SFI: u64 = 0x2;
pub const V8_FILE_TYPE_NATIVE_CODE: u64 = 0x3;
pub const V8_FILE_TYPE_NATIVE_JSFUNC: u64 = 0x4;

/// Global version registry for fast PID lookup in FFI
static PROCESS_VERSIONS: OnceLock<Mutex<HashMap<u32, Version>>> = OnceLock::new();

fn get_version_registry() -> &'static Mutex<HashMap<u32, Version>> {
    PROCESS_VERSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Get V8 offsets for a process (used by FFI)
pub fn get_offsets_for_pid(pid: u32) -> &'static V8Offsets {
    if let Ok(registry) = get_version_registry().lock() {
        if let Some(version) = registry.get(&pid) {
            return get_offsets_for_v8_version(version);
        }
    }
    // Default to latest if not found
    V8_11_OFFSETS
}

fn error_not_v8(pid: u32) -> Error {
    Error::BadInterpreterType(pid, "v8")
}

fn error_not_supported_version(pid: u32, version: Version) -> Error {
    Error::BadInterpreterVersion(pid, "v8", version)
}

// V8/Node.js-specific version extraction utilities
thread_local! {
    static NODE_VERSION_REGEX: OnceCell<Regex> = OnceCell::new();
    static NODE_VERSION_BINARY_REGEX: OnceCell<Regex> = OnceCell::new();
}

const NODE_VERSION_REGEX_STR: &str = r"node-v?(\d+)\.(\d+)\.(\d+)";
// For binary search, match "v18.20.8" format (without "node-" prefix)
const NODE_VERSION_BINARY_REGEX_STR: &str = r"v(\d+)\.(\d+)\.(\d+)";

fn parse_node_version(cap: regex::Captures) -> Option<Version> {
    Some(Version::new(
        cap.get(1)?.as_str().parse().ok()?,
        cap.get(2)?.as_str().parse().ok()?,
        cap.get(3)?.as_str().parse().ok()?,
    ))
}

/// V8 symbols to detect Node.js/V8 processes
const V8_SYMBOLS: [&str; 5] = [
    "v8dbg_type_JSFunction",
    "v8dbg_type_SharedFunctionInfo",
    "v8dbg_off_HeapObject__map",
    "v8::internal::Isolate",
    "V8",
];

/// Check if the mapped file has V8 symbols
fn has_v8_symbols(file: &mut MappedFile) -> Result<bool> {
    file.has_any_symbols_matching(&V8_SYMBOLS)
}

/// Extract Node.js version from filename (e.g., "node-v18.20.8" -> 18.20.8)
fn extract_version_from_filename(file: &MappedFile) -> Option<Version> {
    let path_str = file.path.to_str()?;
    let cap = NODE_VERSION_REGEX.with(|r| {
        r.get_or_init(|| Regex::new(NODE_VERSION_REGEX_STR).unwrap())
            .captures(path_str)
    })?;
    parse_node_version(cap)
}

/// Search for Node.js version string in binary data
fn search_version_in_data(data: &[u8]) -> Option<Version> {
    // Search for version pattern "vX.Y.Z" in binary data
    // Node.js embeds version string deep in the binary (can be at 40MB+)
    // Search entire file, but limit to reasonable size to avoid excessive scanning
    let search_limit = data.len().min(100 * 1024 * 1024); // Search up to 100MB

    for i in 0..search_limit.saturating_sub(20) {
        if data[i] == b'v' && i + 1 < search_limit && data[i + 1].is_ascii_digit() {
            // Potential version string found, parse it
            let end = (i + 20).min(search_limit);
            if let Ok(version_str) = std::str::from_utf8(&data[i..end]) {
                // Use binary-specific regex that matches "vX.Y.Z" format
                if let Some(c) = NODE_VERSION_BINARY_REGEX.with(|r| {
                    r.get_or_init(|| Regex::new(NODE_VERSION_BINARY_REGEX_STR).unwrap())
                        .captures(version_str)
                }) {
                    if let Some(v) = parse_node_version(c) {
                        // Sanity check: Node.js versions should be reasonable
                        if v.major >= 12 && v.major <= 30 {
                            return Some(v);
                        }
                    }
                }
            }
        }
    }

    None
}

/// Read Node.js version from embedded strings in the binary.
/// Node.js embeds version string like "v18.20.8" in the executable.
fn read_node_version_from_binary(file: &MappedFile) -> Option<Version> {
    // If contents not loaded yet, we cannot search.
    if file.contents.is_empty() {
        // Try to read the file directly
        let data = fs::read(&file.path).ok()?;
        return search_version_in_data(&data);
    }

    search_version_in_data(&file.contents)
}

/// Extract Node.js version from file (first filename, then binary data)
fn extract_node_version(file: &MappedFile) -> Option<Version> {
    // First try to extract version from file path
    if let Some(v) = extract_version_from_filename(file) {
        return Some(v);
    }

    // If path doesn't contain version, try to read from binary data
    match read_node_version_from_binary(file) {
        Some(v) => Some(v),
        None => {
            // Could not find version in binary data
            None
        }
    }
}

/// Read V8 version directly from ELF symbols (accurate method).
/// This reads v8::internal::Version::{major,minor,build}_ symbols.
/// Symbol names are C++ mangled: _ZN2v88internal7Version6{major|minor|build}_E
fn read_v8_version_from_symbols(file: &mut MappedFile) -> Result<Option<Version>> {
    file.load()?;
    let obj = object::File::parse(&*file.contents)?;

    // V8 version symbol names (C++ mangled)
    let major_sym = "_ZN2v88internal7Version6major_E";
    let minor_sym = "_ZN2v88internal7Version6minor_E";
    let build_sym = "_ZN2v88internal7Version6build_E";

    // Find all three version symbols
    let mut major: Option<u32> = None;
    let mut minor: Option<u32> = None;
    let mut build: Option<u32> = None;

    for symbol in obj.symbols().chain(obj.dynamic_symbols()) {
        if let Ok(name) = symbol.name() {
            let addr = symbol.address();

            // Read 4-byte value from symbol data
            if name == major_sym {
                if let Ok(section) =
                    obj.section_by_index(symbol.section_index().unwrap_or(object::SectionIndex(0)))
                {
                    if let Ok(data) = section.data() {
                        let offset = (addr - section.address()) as usize;
                        if offset + 4 <= data.len() {
                            major = Some(u32::from_le_bytes([
                                data[offset],
                                data[offset + 1],
                                data[offset + 2],
                                data[offset + 3],
                            ]));
                        }
                    }
                }
            } else if name == minor_sym {
                if let Ok(section) =
                    obj.section_by_index(symbol.section_index().unwrap_or(object::SectionIndex(0)))
                {
                    if let Ok(data) = section.data() {
                        let offset = (addr - section.address()) as usize;
                        if offset + 4 <= data.len() {
                            minor = Some(u32::from_le_bytes([
                                data[offset],
                                data[offset + 1],
                                data[offset + 2],
                                data[offset + 3],
                            ]));
                        }
                    }
                }
            } else if name == build_sym {
                if let Ok(section) =
                    obj.section_by_index(symbol.section_index().unwrap_or(object::SectionIndex(0)))
                {
                    if let Ok(data) = section.data() {
                        let offset = (addr - section.address()) as usize;
                        if offset + 4 <= data.len() {
                            build = Some(u32::from_le_bytes([
                                data[offset],
                                data[offset + 1],
                                data[offset + 2],
                                data[offset + 3],
                            ]));
                        }
                    }
                }
            }
        }
    }

    // If we found both major and minor, construct Version
    // Note: build version is less critical and often 0 in some V8 builds
    if let (Some(maj), Some(min)) = (major, minor) {
        // Build might be available, default to 0 if not found
        let bld = build.unwrap_or(0);
        return Ok(Some(Version::new(maj as u64, min as u64, bld as u64)));
    }

    Ok(None)
}

/// Fallback: Map Node.js version to approximate V8 version.
/// Note: This is less accurate than reading from ELF symbols.
fn node_to_v8_version(node_version: &Version) -> Option<Version> {
    match (node_version.major, node_version.minor) {
        // Node.js 23.x → V8 12.9.202.26 ~ 12.9.202.28
        (23, _) => Some(Version::new(12, 9, 202)),
        // Node.js 22.x → V8 12.4.254.14 ~ 12.4.254.21
        (22, _) => Some(Version::new(12, 4, 254)),
        // Node.js 21.x → V8 11.8.172.13 ~ 11.8.172.17
        (21, _) => Some(Version::new(11, 8, 172)),
        // Node.js 20.x → V8 11.3.244.4 ~ 11.3.244.8
        (20, _) => Some(Version::new(11, 3, 244)),
        // Node.js 19.x → V8 10.7.193.13 ~ 10.8.168.25
        (19, _) => Some(Version::new(10, 8, 168)),
        // Node.js 18.x → V8 10.1.124.8 ~ 10.2.154.26
        (18, _) => Some(Version::new(10, 2, 154)),
        // Node.js 17.x → V8 9.5.172.21 ~ 9.6.180.15
        (17, _) => Some(Version::new(9, 6, 180)),
        // Node.js 16.x → V8 9.0.257.17 ~ 9.4.146.26
        (16, _) => Some(Version::new(9, 4, 146)),
        // Default to latest for unknown versions
        _ => Some(Version::new(12, 9, 202)),
    }
}

struct Interpreter {
    exe: MappedFile,
    node_version: Version,
    v8_version: Version,
}

impl Interpreter {
    fn new(pid: u32, exe_area: &MemoryArea) -> Result<Self> {
        // Build namespace-aware path using /proc/PID/root to access files
        // from the target process's mount namespace
        let real_path = Self::build_namespaced_path(pid, &exe_area.path);

        let mut exe = MappedFile::from_str(&real_path, exe_area.m_start);

        if !has_v8_symbols(&mut exe)? {
            // Try fallback to direct path if namespaced path failed
            exe = MappedFile::from_str(&exe_area.path, exe_area.m_start);

            if !has_v8_symbols(&mut exe)? {
                return Err(error_not_v8(pid));
            }
        }

        // Try to get Node.js version for informational purposes
        let node_version_opt = extract_node_version(&exe);
        let has_node_version = node_version_opt.is_some();
        let node_version = node_version_opt.unwrap_or_else(|| {
            // If version detection fails, use a reasonable default for Node.js 18.x
            // This allows version check to pass while we rely on V8 ELF symbols for accuracy
            warn!(
                "Process#{pid} Failed to detect Node.js version from path or binary, using default 20.0.0"
            );
            Version::new(20, 0, 0)
        });

        // Try to read V8 version directly from ELF symbols (most accurate)
        let v8_version = match read_v8_version_from_symbols(&mut exe) {
            Ok(Some(version)) => {
                if has_node_version {
                    trace!(
                        "Process#{pid} V8 version from ELF symbols: {} (Node: {})",
                        version,
                        node_version
                    );
                } else {
                    trace!(
                        "Process#{pid} V8 version from ELF symbols: {} (Node version unknown, using default {})",
                        version,
                        node_version
                    );
                }
                version
            }
            Ok(None) => {
                trace!(
                    "Process#{pid} V8 ELF symbols not found, using Node mapping: Node {}",
                    node_version
                );
                // Fallback: Try Node.js version from path + mapping
                node_to_v8_version(&node_version).unwrap_or_else(|| Version::new(11, 3, 244))
            }
            Err(e) => {
                warn!(
                    "Process#{pid} Failed to read V8 ELF symbols: {:?}, using Node mapping",
                    e
                );
                // Fallback: Try Node.js version from path + mapping
                node_to_v8_version(&node_version).unwrap_or_else(|| Version::new(11, 3, 244))
            }
        };

        Ok(Self {
            exe,
            node_version,
            v8_version,
        })
    }

    /// Build a namespace-aware path using /proc/PID/root prefix.
    /// This allows accessing files from the target process's mount namespace.
    fn build_namespaced_path(pid: u32, path: &str) -> String {
        if path.starts_with('/') {
            format!("/proc/{}/root{}", pid, path)
        } else {
            path.to_string()
        }
    }

    fn isolate_address(&mut self) -> Result<u64> {
        // 在实际实现中需要从进程内存中动态获取isolate地址
        // 这里简化为返回一个固定值
        self.exe
            .find_symbol_address("v8::internal::Isolate::Current")
            .map(|addr| addr.unwrap_or(0))
    }
}

pub struct InterpreterInfo {
    pub node_version: Version,
    pub v8_version: Version,
    pub isolate_address: u64,
}

impl InterpreterInfo {
    pub fn new(pid: u32) -> Result<Self> {
        trace!("find V8 interpreter info for process#{pid}");
        let exe_path: PathBuf = ["/proc", &pid.to_string(), "exe"].iter().collect();
        let exe_path = fs::read_link(&exe_path)?;
        let exe_path_str = exe_path.to_str();

        let mm = get_memory_mappings(pid)?;
        let Some(exe_area) = mm.iter().find(|m| {
            Some(m.path.as_str()) == exe_path_str
                || m.path.contains("node")
                || m.path.ends_with("node")
        }) else {
            warn!("Process#{pid} Node.js executable not found in maps");
            return Err(error_not_v8(pid));
        };

        let mut intp = Interpreter::new(pid, exe_area)?;

        // Check if the Node.js version is supported
        let req = VersionReq::parse(">=16.0.0, <24.0.0").unwrap();
        if !req.matches(&intp.node_version) {
            return Err(error_not_supported_version(pid, intp.node_version.clone()));
        }

        Ok(Self {
            node_version: intp.node_version.clone(),
            v8_version: intp.v8_version.clone(),
            isolate_address: intp.isolate_address()?,
        })
    }
}

#[repr(C)]
pub struct V8UnwindInfo {
    pub isolate_address: u64,
    pub offsets_id: u8,
    pub version: u32,
}

// V8ProcInfo: Matches the C v8_proc_info_t structure in perf_profiler.h
// This is what eBPF expects in the v8_unwind_info_map
// IMPORTANT: Field order and padding must exactly match C structure
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct V8ProcInfo {
    // Heap Object Offsets
    pub off_heap_object_map: u16,

    // JSFunction Offsets
    pub off_jsfunction_shared: u16,
    pub off_jsfunction_code: u16,

    // Code Object Offsets
    pub off_code_instruction_start: u16,
    pub off_code_instruction_size: u16,
    pub off_code_flags: u16,

    // Type IDs (for validation)
    pub type_jsfunction_first: u16,
    pub type_jsfunction_last: u16,
    pub type_shared_function_info: u16,
    pub type_code: u16,

    // Frame Pointer Offsets (relative to FP)
    pub fp_marker: i16,
    pub fp_function: i16,
    pub fp_bytecode_offset: i16,

    // Explicit padding for u32 alignment (C compiler adds this automatically)
    _padding: u16,

    // Version & Metadata
    pub v8_version: u32,
    pub codekind_mask: u32,
    pub codekind_shift: u8,
    pub codekind_baseline: u8,
    pub reserved: u16,

    // Debug counters
    pub unwinding_attempted: u64,
    pub unwinding_success: u64,
    pub unwinding_failed: u64,
}

// Compile-time size check: Ensure V8ProcInfo matches C v8_proc_info_t size
// Expected: 10*u16 + 3*i16 + 1*u16(padding) + 2*u32 + 2*u8 + 1*u16 + 3*u64
//         = 20 + 6 + 2 + 8 + 2 + 2 + 24 = 64 bytes
const _: () = assert!(
    std::mem::size_of::<V8ProcInfo>() == 64,
    "V8ProcInfo size must be 64 bytes to match C v8_proc_info_t"
);

impl V8ProcInfo {
    pub fn from_offsets(offsets: &V8Offsets, version: u32) -> Self {
        let proc_info = V8ProcInfo {
            // Heap Object Offsets - these would come from vmstructs if we had them
            // For now, use common values that work across V8 versions
            off_heap_object_map: 0, // First field in HeapObject

            // JSFunction Offsets
            off_jsfunction_shared: offsets.js_function.shared,
            off_jsfunction_code: offsets.js_function.code,

            // Code Object Offsets
            off_code_instruction_start: offsets.code.instruction_start as u16,
            off_code_instruction_size: offsets.code.instruction_size as u16,
            off_code_flags: offsets.code.flags as u16,

            // Type IDs - read from V8Offsets structure (version-specific)
            type_jsfunction_first: offsets.v8_type.js_function_first,
            type_jsfunction_last: offsets.v8_type.js_function_last,
            type_shared_function_info: offsets.v8_type.shared_function_info,
            type_code: offsets.v8_type.code, // V8 Code object type ID (version-specific)

            // Frame Pointer Offsets
            fp_marker: offsets.frame_pointers.marker,
            fp_function: offsets.frame_pointers.function,
            fp_bytecode_offset: offsets.frame_pointers.bytecode_offset,

            // Explicit padding
            _padding: 0,

            // Version & Metadata
            v8_version: version,
            codekind_mask: offsets.codekind.mask, // CodeKindFieldMask (version-specific)
            codekind_shift: offsets.codekind.shift, // CodeKindFieldShift (version-specific)
            codekind_baseline: offsets.codekind.baseline, // Baseline CodeKind (version-specific)
            reserved: 0,

            // Debug counters (initialized to zero)
            unwinding_attempted: 0,
            unwinding_success: 0,
            unwinding_failed: 0,
        };

        // Verify struct size

        proc_info
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8Offsets {
    pub frame_pointers: V8FramePointers,
    pub js_function: V8JSFunction,
    pub shared_function_info: V8SharedFunctionInfo,
    pub code: V8Code,
    pub script: V8Script,
    pub bytecode_array: V8BytecodeArray,
    pub v8_type: V8Type,
    pub v8_fixed: V8Fixed,
    pub scope_info_index: V8ScopeInfoIndex,
    pub deopt_data_index: V8DeoptimizationDataIndex,
    pub heap_object: V8HeapObject,
    pub map: V8Map,
    pub frame_types: V8FrameTypes,
    pub codekind: V8CodeKind,
}

impl Default for V8Offsets {
    fn default() -> Self {
        // Return V8 9.x offsets as default (Node.js 16.x)
        *V8_9_OFFSETS
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8FramePointers {
    pub marker: i16,
    pub function: i16,
    pub bytecode_offset: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8JSFunction {
    pub shared: u16,
    pub code: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8SharedFunctionInfo {
    pub name_or_scope_info: u16,
    pub function_data: u16,
    pub script_or_debug_info: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8Script {
    pub name: u16,
    pub source: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8Code {
    pub instruction_start: u16,
    pub instruction_size: u16,
    pub flags: u16,
    pub deoptimization_data: u16,
    pub source_position_table: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8BytecodeArray {
    pub source_position_table: u16,
}

// V8 Type IDs for object type checking
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8Type {
    pub scope_info: u16,
    pub shared_function_info: u16,
    pub js_function_first: u16,
    pub js_function_last: u16,
    pub string_first: u16,
    pub script: u16,
    pub code: u16, // Code object type ID (v8dbg_type_Code__CODE_TYPE)
}

// V8 Fixed Array/Object type boundaries
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8Fixed {
    pub first_nonstring_type: u16,
    pub string_representation_mask: u16,
    pub seq_string_tag: u16,
    pub cons_string_tag: u16,
    pub thin_string_tag: u16,
}

// V8 ScopeInfo internal structure indices
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8ScopeInfoIndex {
    pub first_vars: u8,
    pub n_context_locals: u8,
}

// V8 DeoptimizationData array indices
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8DeoptimizationDataIndex {
    pub inlined_function_count: u8,
    pub literal_array: u8,
    pub shared_function_info: u8,
    pub inlining_positions: u8,
}

// V8 Frame Type values (version-specific)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8FrameTypes {
    pub entry_frame: u8,
    pub construct_entry_frame: u8,
    pub exit_frame: u8,
    pub wasm_frame: u8,
    pub wasm_to_js_frame: u8,
    pub wasm_to_js_function_frame: u8, // V8 11+ only
    pub js_to_wasm_frame: u8,
    pub wasm_debug_break_frame: u8,
    pub stack_switch_frame: u8, // V8 10+ only
    pub wasm_exit_frame: u8,
    pub c_wasm_entry_frame: u8,
    pub wasm_compile_lazy_frame: u8,  // V8 9-10 only
    pub wasm_liftoff_setup_frame: u8, // V8 11+ only
    pub interpreted_frame: u8,
    pub baseline_frame: u8,
    pub maglev_frame: u8,   // V8 11+ only
    pub turbofan_frame: u8, // V8 11+, replaces optimized_frame
    pub stub_frame: u8,
    pub turbofan_stub_with_context_frame: u8, // V8 11+ only
    pub builtin_continuation_frame: u8,
    pub js_builtin_continuation_frame: u8,
    pub js_builtin_continuation_with_catch_frame: u8,
    pub internal_frame: u8,
    pub construct_frame: u8,
    pub fast_construct_frame: u8, // V8 12+ only
    pub builtin_frame: u8,
    pub builtin_exit_frame: u8,
    pub native_frame: u8,
    pub api_callback_exit_frame: u8, // V8 12+ only
    pub irregexp_frame: u8,          // V8 11+ only

    // Legacy field for backward compatibility (V8 9-10)
    pub optimized_frame: u8, // V8 9-10, replaced by turbofan_frame in V8 11+
}

// V8 HeapObject structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8HeapObject {
    pub map: u16, // Offset to Map object
}

// V8 Map structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8Map {
    pub instance_type: u16, // Offset to instance_type field
}

// V8 CodeKind constants (version-specific)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8CodeKind {
    pub mask: u32,       // CodeKindFieldMask
    pub shift: u8,       // CodeKindFieldShift
    pub baseline: u8,    // CodeKindBaseline
    pub interpreted: u8, // CodeKindInterpretedFunction
}

// V8 9.x offsets (Node.js 16.x)
pub const V8_9_OFFSETS: &V8Offsets = &V8Offsets {
    frame_pointers: V8FramePointers {
        marker: -8,           // v8dbg_off_fp_context = 0xf8 relative to FP
        function: -16,        // v8dbg_off_fp_function = 0xf0 relative to FP
        bytecode_offset: -40, // v8dbg_off_fp_bytecode_offset = 0xd8 relative to FP
    },
    js_function: V8JSFunction {
        shared: 24, // v8dbg_class_JSFunction__shared__SharedFunctionInfo
        code: 48,   // v8dbg_class_JSFunction__raw_code__CodeT
    },
    shared_function_info: V8SharedFunctionInfo {
        name_or_scope_info: 16, // v8dbg_class_SharedFunctionInfo__name_or_scope_info__Object
        function_data: 8,       // v8dbg_class_SharedFunctionInfo__function_data__Object
        script_or_debug_info: 32, // v8dbg_class_SharedFunctionInfo__script_or_debug_info__HeapObject
    },
    code: V8Code {
        instruction_start: 96, // v8dbg_class_Code__instruction_start__uintptr_t (V8 9.x) = 0x60
        instruction_size: 40,  // v8dbg_class_Code__instruction_size__int (V8 9.x) = 0x28
        flags: 48,             // Code::Flags = 0x30 (from OTel log)
        deoptimization_data: 16, // Code::DeoptimizationData = 0x10 (from OTel log)
        source_position_table: 24, // v8dbg_class_Code__source_position_table__ByteArray = 0x18
    },
    script: V8Script {
        name: 16,  // v8dbg_class_Script__name__Object = 0x10
        source: 8, // Script::Source = 0x8 (from OTel log, different from vmstructs!)
    },
    bytecode_array: V8BytecodeArray {
        source_position_table: 32, // BytecodeArray::SourcePositionTable = 0x20
    },
    v8_type: V8Type {
        scope_info: 178,           // v8dbg_type_ScopeInfo__SCOPE_INFO_TYPE (V8 9.4)
        shared_function_info: 179, // v8dbg_type_SharedFunctionInfo__SHARED_FUNCTION_INFO_TYPE
        js_function_first: 1059,   // v8dbg_type_JSFunction__JS_FUNCTION_TYPE
        js_function_last: 1059,
        string_first: 0,
        script: 112, // v8dbg_type_Script__SCRIPT_TYPE
        code: 162,   // v8dbg_type_Code__CODE_TYPE (V8 9.4)
    },
    v8_fixed: V8Fixed {
        first_nonstring_type: 64,        // v8dbg_FirstNonstringType (V8 9.4)
        string_representation_mask: 0x7, // v8dbg_StringRepresentationMask
        seq_string_tag: 0x0,             // v8dbg_SeqStringTag
        cons_string_tag: 0x1,            // v8dbg_ConsStringTag
        thin_string_tag: 0x5,            // v8dbg_ThinStringTag
    },
    scope_info_index: V8ScopeInfoIndex {
        first_vars: 3,
        n_context_locals: 2,
    },
    deopt_data_index: V8DeoptimizationDataIndex {
        inlined_function_count: 1, // DeoptimizationDataIndex::InlinedFunctionCount = 0x1
        literal_array: 2,          // DeoptimizationDataIndex::LiteralArray = 0x2
        shared_function_info: 6,   // DeoptimizationDataIndex::SharedFunctionInfo = 0x6
        inlining_positions: 7,     // DeoptimizationDataIndex::InliningPositions = 0x7
    },
    heap_object: V8HeapObject { map: 0 },
    map: V8Map { instance_type: 12 },
    frame_types: V8FrameTypes {
        entry_frame: 1,
        construct_entry_frame: 2,
        exit_frame: 3,
        wasm_frame: 4,
        wasm_to_js_frame: 5,
        wasm_to_js_function_frame: 0, // Not in V8 9
        js_to_wasm_frame: 6,
        wasm_debug_break_frame: 7,
        stack_switch_frame: 0, // Not in V8 9
        wasm_exit_frame: 9,
        c_wasm_entry_frame: 8,
        wasm_compile_lazy_frame: 10, // V8 9 only
        wasm_liftoff_setup_frame: 0, // V8 11+ only
        interpreted_frame: 11,
        baseline_frame: 12,
        maglev_frame: 0,   // Not in V8 9
        turbofan_frame: 0, // Not in V8 9, use optimized_frame
        stub_frame: 14,
        turbofan_stub_with_context_frame: 0, // Not in V8 9
        builtin_continuation_frame: 15,
        js_builtin_continuation_frame: 16,
        js_builtin_continuation_with_catch_frame: 17,
        internal_frame: 18,
        construct_frame: 19,
        fast_construct_frame: 0, // Not in V8 9
        builtin_frame: 20,
        builtin_exit_frame: 21,
        native_frame: 22,
        api_callback_exit_frame: 0, // Not in V8 9
        irregexp_frame: 0,          // Not in V8 9
        optimized_frame: 13,        // V8 9-10, replaced by turbofan_frame in V8 11+
    },
    codekind: V8CodeKind {
        mask: 15,        // CodeKind::FieldMask = 0xf
        shift: 0,        // CodeKind::FieldShift = 0x0
        baseline: 11,    // CodeKind::Baseline = 0xb
        interpreted: 10, // CodeKindInterpretedFunction (inferred from V8 10)
    },
};

// V8 10.x offsets (Node.js 18.x)
pub const V8_10_OFFSETS: &V8Offsets = &V8Offsets {
    frame_pointers: V8FramePointers {
        marker: -8,           // v8dbg_off_fp_context
        function: -16,        // v8dbg_off_fp_function (was incorrectly -8)
        bytecode_offset: -40, // v8dbg_off_fp_bytecode_offset (was incorrectly -24)
    },
    js_function: V8JSFunction {
        shared: 24, // v8dbg_class_JSFunction__shared__SharedFunctionInfo (V8 10.2)
        code: 48,   // v8dbg_class_JSFunction__code__CodeT (V8 10.2)
    },
    shared_function_info: V8SharedFunctionInfo {
        name_or_scope_info: 16, // v8dbg_class_SharedFunctionInfo__name_or_scope_info__Object (V8 10.2)
        function_data: 8,       // v8dbg_class_SharedFunctionInfo__function_data__Object (V8 10.2)
        script_or_debug_info: 32, // v8dbg_class_SharedFunctionInfo__script_or_debug_info__HeapObject (V8 10.2)
    },
    code: V8Code {
        instruction_start: 128, // v8dbg_class_Code__instruction_start__uintptr_t (V8 10.x) = 0x80
        instruction_size: 40,   // v8dbg_class_Code__instruction_size__int (V8 10.x) = 0x28
        flags: 48,              // v8dbg_class_Code__flags__uint32_t (V8 10.x) = 0x30
        deoptimization_data: 16, // Code::DeoptimizationData (V8 10.x) = 0x10
        source_position_table: 24, // Code::SourcePositionTable (V8 10.x) = 0x18
    },
    script: V8Script {
        name: 16,  // v8dbg_class_Script__name__Object (V8 10.2)
        source: 8, // v8dbg_class_Script__source__Object (V8 10.2)
    },
    bytecode_array: V8BytecodeArray {
        source_position_table: 32, // BytecodeArray::SourcePositionTable (V8 10.x) = 0x20
    },
    v8_type: V8Type {
        scope_info: 256,           // v8dbg_type_ScopeInfo__SCOPE_INFO_TYPE (V8 10.2)
        shared_function_info: 257, // v8dbg_type_SharedFunctionInfo__SHARED_FUNCTION_INFO_TYPE
        js_function_first: 2065,   // FirstJSFunctionType (V8 10.x) = 0x811
        js_function_last: 2079,    // LastJSFunctionType (V8 10.x) = 0x81f
        string_first: 0,
        script: 170, // v8dbg_type_Script__SCRIPT_TYPE
        code: 240,   // v8dbg_type_Code__CODE_TYPE (V8 10.2)
    },
    v8_fixed: V8Fixed {
        first_nonstring_type: 128,       // v8dbg_FirstNonstringType
        string_representation_mask: 0x7, // v8dbg_StringRepresentationMask
        seq_string_tag: 0x0,             // v8dbg_SeqStringTag
        cons_string_tag: 0x1,            // v8dbg_ConsStringTag
        thin_string_tag: 0x5,            // v8dbg_ThinStringTag
    },
    scope_info_index: V8ScopeInfoIndex {
        first_vars: 3, // Assume same as V8 9.x
        n_context_locals: 2,
    },
    deopt_data_index: V8DeoptimizationDataIndex {
        inlined_function_count: 1, // DeoptimizationDataInlinedFunctionCountIndex (V8 10.x) = 0x1
        literal_array: 2,          // DeoptimizationDataLiteralArrayIndex (V8 10.x) = 0x2
        shared_function_info: 6,   // DeoptimizationDataSharedFunctionInfoIndex (V8 10.x) = 0x6
        inlining_positions: 7,     // DeoptimizationDataInliningPositionsIndex (V8 10.x) = 0x7
    },
    heap_object: V8HeapObject { map: 0 },
    map: V8Map { instance_type: 12 },
    frame_types: V8FrameTypes {
        entry_frame: 1,
        construct_entry_frame: 2,
        exit_frame: 3,
        wasm_frame: 4,
        wasm_to_js_frame: 5,
        wasm_to_js_function_frame: 0, // Not in V8 10
        js_to_wasm_frame: 6,
        wasm_debug_break_frame: 8,
        stack_switch_frame: 7, // V8 10+
        wasm_exit_frame: 10,
        c_wasm_entry_frame: 9,
        wasm_compile_lazy_frame: 11, // V8 9-10 only
        wasm_liftoff_setup_frame: 0, // V8 11+ only
        interpreted_frame: 12,
        baseline_frame: 13,
        maglev_frame: 0,   // Not in V8 10
        turbofan_frame: 0, // Not in V8 10, use optimized_frame
        stub_frame: 15,
        turbofan_stub_with_context_frame: 0, // Not in V8 10
        builtin_continuation_frame: 16,
        js_builtin_continuation_frame: 17,
        js_builtin_continuation_with_catch_frame: 18,
        internal_frame: 19,
        construct_frame: 20,
        fast_construct_frame: 0, // Not in V8 10
        builtin_frame: 21,
        builtin_exit_frame: 22,
        native_frame: 23,
        api_callback_exit_frame: 0, // Not in V8 10
        irregexp_frame: 0,          // Not in V8 10
        optimized_frame: 14,        // V8 9-10, replaced by turbofan_frame in V8 11+
    },
    codekind: V8CodeKind {
        mask: 15,        // v8dbg_CodeKindFieldMask (V8 10)
        shift: 0,        // v8dbg_CodeKindFieldShift (V8 10)
        baseline: 11,    // v8dbg_CodeKindBaseline (V8 10)
        interpreted: 10, // v8dbg_CodeKindInterpretedFunction (V8 10)
    },
};

// V8 11.x offsets (Node.js 20.x)
pub const V8_11_OFFSETS: &V8Offsets = &V8Offsets {
    frame_pointers: V8FramePointers {
        marker: -8,           // v8dbg_off_fp_context
        function: -16,        // v8dbg_off_fp_function
        bytecode_offset: -40, // v8dbg_off_fp_bytecode_offset
    },
    js_function: V8JSFunction {
        shared: 24, // v8dbg_class_JSFunction__shared__SharedFunctionInfo
        code: 48,   // 0x30 - From OpenTelemetry runtime logs (V8 11.x)
    },
    shared_function_info: V8SharedFunctionInfo {
        name_or_scope_info: 16, // v8dbg_class_SharedFunctionInfo__name_or_scope_info__Object
        function_data: 8,       // v8dbg_class_SharedFunctionInfo__function_data__Object
        script_or_debug_info: 32, // v8dbg_class_SharedFunctionInfo__script_or_debug_info__HeapObject
    },
    code: V8Code {
        instruction_start: 40,     // 0x28 - From OpenTelemetry runtime logs (V8 11.x)
        instruction_size: 56,      // 0x38 - From OpenTelemetry runtime logs (V8 11.x)
        flags: 48,                 // 0x30 - From OpenTelemetry runtime logs (V8 11.x)
        deoptimization_data: 16, // 0x10 - v8dbg_class_Code__deoptimization_data__FixedArray (V8 11.x)
        source_position_table: 24, // 0x18 - v8dbg_class_Code__source_position_table__ByteArray (V8 11.x)
    },
    script: V8Script {
        name: 16,  // v8dbg_class_Script__name__Object (V8 11)
        source: 8, // v8dbg_class_Script__source__Object (V8 11)
    },
    bytecode_array: V8BytecodeArray {
        source_position_table: 8,
    },
    v8_type: V8Type {
        scope_info: 261,           // v8dbg_type_ScopeInfo__SCOPE_INFO_TYPE
        shared_function_info: 262, // v8dbg_type_SharedFunctionInfo__SHARED_FUNCTION_INFO_TYPE
        js_function_first: 2066,   // v8dbg_type_JSFunction__JS_FUNCTION_TYPE
        js_function_last: 2080,    // 0x820 - From OpenTelemetry runtime logs (V8 11.x)
        string_first: 0,           // String types start at 0
        script: 167,               // v8dbg_type_Script__SCRIPT_TYPE
        code: 245,                 // v8dbg_type_Code__CODE_TYPE (V8 11)
    },
    v8_fixed: V8Fixed {
        first_nonstring_type: 128,       // v8dbg_FirstNonstringType
        string_representation_mask: 0x7, // v8dbg_StringRepresentationMask
        seq_string_tag: 0x0,             // v8dbg_SeqStringTag
        cons_string_tag: 0x1,            // v8dbg_ConsStringTag
        thin_string_tag: 0x5,            // v8dbg_ThinStringTag
    },
    scope_info_index: V8ScopeInfoIndex {
        first_vars: 3,       // v8dbg_scopeinfo_idx_first_vars
        n_context_locals: 2, // v8dbg_scopeinfo_idx_ncontextlocals
    },
    deopt_data_index: V8DeoptimizationDataIndex {
        inlined_function_count: 1, // v8dbg_DeoptimizationDataInlinedFunctionCountIndex (V8 11.x)
        literal_array: 2,          // v8dbg_DeoptimizationDataLiteralArrayIndex (V8 11.x)
        shared_function_info: 6,   // v8dbg_DeoptimizationDataSharedFunctionInfoIndex (V8 11.x)
        inlining_positions: 7,     // v8dbg_DeoptimizationDataInliningPositionsIndex (V8 11.x)
    },
    heap_object: V8HeapObject {
        map: 0, // v8dbg_class_HeapObject__map__Map
    },
    map: V8Map {
        instance_type: 12, // v8dbg_class_Map__instance_type__uint16_t
    },
    frame_types: V8FrameTypes {
        entry_frame: 1,
        construct_entry_frame: 2,
        exit_frame: 3,
        wasm_frame: 4,
        wasm_to_js_frame: 5,
        wasm_to_js_function_frame: 6, // V8 11+
        js_to_wasm_frame: 7,
        wasm_debug_break_frame: 9,
        stack_switch_frame: 8, // V8 10+
        wasm_exit_frame: 11,
        c_wasm_entry_frame: 10,
        wasm_compile_lazy_frame: 0,   // V8 9-10 only
        wasm_liftoff_setup_frame: 12, // V8 11+
        interpreted_frame: 13,
        baseline_frame: 14,
        maglev_frame: 15,   // V8 11+
        turbofan_frame: 16, // V8 11+, replaces optimized_frame
        stub_frame: 17,
        turbofan_stub_with_context_frame: 18, // V8 11+
        builtin_continuation_frame: 19,
        js_builtin_continuation_frame: 20,
        js_builtin_continuation_with_catch_frame: 21,
        internal_frame: 22,
        construct_frame: 23,
        fast_construct_frame: 0, // V8 12+
        builtin_frame: 24,
        builtin_exit_frame: 25,
        native_frame: 26,
        api_callback_exit_frame: 0, // V8 12+
        irregexp_frame: 27,         // V8 11+
        optimized_frame: 0,         // V8 9-10 only, use turbofan_frame in V8 11+
    },
    codekind: V8CodeKind {
        mask: 15,        // v8dbg_CodeKindFieldMask (V8 11)
        shift: 0,        // v8dbg_CodeKindFieldShift (V8 11)
        baseline: 11,    // v8dbg_CodeKindBaseline (V8 11)
        interpreted: 10, // v8dbg_CodeKindInterpretedFunction (V8 11)
    },
};

// V8 12.x offsets (Node.js 22.x)
pub const V8_12_OFFSETS: &V8Offsets = &V8Offsets {
    frame_pointers: V8FramePointers {
        marker: -8,           // v8dbg_off_fp_context
        function: -16,        // v8dbg_off_fp_function
        bytecode_offset: -40, // v8dbg_off_fp_bytecode_offset
    },
    js_function: V8JSFunction {
        shared: 32, // v8dbg_class_JSFunction__shared__SharedFunctionInfo
        code: 24,   // v8dbg_class_JSFunction__code__Tagged_Code_
    },
    shared_function_info: V8SharedFunctionInfo {
        name_or_scope_info: 16, // v8dbg_class_SharedFunctionInfo__name_or_scope_info__Tagged_Object_
        function_data: 8,       // v8dbg_class_SharedFunctionInfo__function_data__Object
        script_or_debug_info: 32, // v8dbg_class_SharedFunctionInfo__raw_script__Tagged_Object_
    },
    code: V8Code {
        instruction_start: 40,     // v8dbg_class_Code__instruction_start__Address
        instruction_size: 52,      // v8dbg_class_Code__instruction_size__int
        flags: 48,                 // v8dbg_class_Code__flags__uint32_t
        deoptimization_data: 8, // v8dbg_class_Code__deoptimization_data_or_interpreter_data__Tagged_Object_
        source_position_table: 16, // v8dbg_class_Code__position_table__Tagged_Object_
    },
    script: V8Script {
        name: 16,  // v8dbg_class_Script__name__Object
        source: 8, // v8dbg_class_Script__source__Object
    },
    bytecode_array: V8BytecodeArray {
        source_position_table: 8,
    },
    v8_type: V8Type {
        scope_info: 272,           // v8dbg_type_ScopeInfo__SCOPE_INFO_TYPE
        shared_function_info: 274, // v8dbg_type_SharedFunctionInfo__SHARED_FUNCTION_INFO_TYPE
        js_function_first: 2066,   // v8dbg_FirstJSFunctionType
        js_function_last: 2082,    // v8dbg_LastJSFunctionType
        string_first: 0,           // String types start at 0
        script: 167,               // v8dbg_type_Script__SCRIPT_TYPE
        code: 206,                 // v8dbg_type_Code__CODE_TYPE
    },
    v8_fixed: V8Fixed {
        first_nonstring_type: 128,       // v8dbg_FirstNonstringType
        string_representation_mask: 0x7, // v8dbg_StringRepresentationMask
        seq_string_tag: 0x0,             // v8dbg_SeqStringTag
        cons_string_tag: 0x1,            // v8dbg_ConsStringTag
        thin_string_tag: 0x5,            // v8dbg_ThinStringTag
    },
    scope_info_index: V8ScopeInfoIndex {
        first_vars: 3,       // v8dbg_scopeinfo_idx_first_vars
        n_context_locals: 2, // v8dbg_scopeinfo_idx_ncontextlocals
    },
    deopt_data_index: V8DeoptimizationDataIndex {
        inlined_function_count: 1, // v8dbg_DeoptimizationDataInlinedFunctionCountIndex
        literal_array: 2,          // v8dbg_DeoptimizationDataLiteralArrayIndex
        shared_function_info: 6,   // v8dbg_DeoptimizationDataSharedFunctionInfoIndex
        inlining_positions: 7,     // v8dbg_DeoptimizationDataInliningPositionsIndex
    },
    heap_object: V8HeapObject {
        map: 0, // v8dbg_class_HeapObject__map__Map
    },
    map: V8Map {
        instance_type: 12, // v8dbg_class_Map__instance_type__uint16_t
    },
    frame_types: V8FrameTypes {
        entry_frame: 1,
        construct_entry_frame: 2,
        exit_frame: 3,
        wasm_frame: 4,
        wasm_to_js_frame: 5,
        wasm_to_js_function_frame: 6, // V8 11+
        js_to_wasm_frame: 7,
        wasm_debug_break_frame: 9,
        stack_switch_frame: 8, // V8 10+
        wasm_exit_frame: 11,
        c_wasm_entry_frame: 10,
        wasm_compile_lazy_frame: 0,   // V8 9-10 only
        wasm_liftoff_setup_frame: 12, // V8 11+
        interpreted_frame: 13,
        baseline_frame: 14,
        maglev_frame: 15,   // V8 11+
        turbofan_frame: 16, // V8 11+, replaces optimized_frame
        stub_frame: 17,
        turbofan_stub_with_context_frame: 18, // V8 11+
        builtin_continuation_frame: 19,
        js_builtin_continuation_frame: 20,
        js_builtin_continuation_with_catch_frame: 21,
        internal_frame: 22,
        construct_frame: 23,
        fast_construct_frame: 24, // V8 12+
        builtin_frame: 25,
        builtin_exit_frame: 26,
        native_frame: 28,
        api_callback_exit_frame: 27, // V8 12+
        irregexp_frame: 29,          // V8 11+ (27 in V8 11, 29 in V8 12)
        optimized_frame: 0,          // V8 9-10 only, use turbofan_frame in V8 11+
    },
    codekind: V8CodeKind {
        mask: 15,       // v8dbg_CodeKindFieldMask (V8 12)
        shift: 0,       // v8dbg_CodeKindFieldShift (V8 12)
        baseline: 10,   // v8dbg_CodeKindBaseline (V8 12)
        interpreted: 9, // v8dbg_CodeKindInterpretedFunction (V8 12)
    },
};

// V8 9.6.x offsets (Node.js 17.x - odd version)
pub const V8_9_6_OFFSETS: &V8Offsets = &V8Offsets {
    frame_pointers: V8FramePointers {
        marker: -8,
        function: -16,
        bytecode_offset: -40,
    },
    js_function: V8JSFunction {
        shared: 24,
        code: 48,
    },
    shared_function_info: V8SharedFunctionInfo {
        name_or_scope_info: 16,
        function_data: 8,
        script_or_debug_info: 32,
    },
    code: V8Code {
        instruction_start: 128,    // 0x80
        instruction_size: 40,      // 0x28
        flags: 48,                 // 0x30
        deoptimization_data: 16,   // 0x10
        source_position_table: 24, // 0x18
    },
    script: V8Script {
        name: 16,
        source: 8,
    },
    bytecode_array: V8BytecodeArray {
        source_position_table: 32, // 0x20
    },
    v8_type: V8Type {
        scope_info: 177,           // 0xb1
        shared_function_info: 178, // 0xb2
        js_function_first: 2060,   // 0x80c
        js_function_last: 2074,    // 0x81a
        string_first: 0,
        script: 111, // 0x6f
        code: 161,   // 0xa1
    },
    v8_fixed: V8Fixed {
        first_nonstring_type: 64, // 0x40
        string_representation_mask: 0x7,
        seq_string_tag: 0x0,
        cons_string_tag: 0x1,
        thin_string_tag: 0x5,
    },
    scope_info_index: V8ScopeInfoIndex {
        first_vars: 3,
        n_context_locals: 2,
    },
    deopt_data_index: V8DeoptimizationDataIndex {
        inlined_function_count: 1,
        literal_array: 2,
        shared_function_info: 6,
        inlining_positions: 7,
    },
    heap_object: V8HeapObject { map: 0 },
    map: V8Map { instance_type: 12 },
    frame_types: V8FrameTypes {
        entry_frame: 1,
        construct_entry_frame: 2,
        exit_frame: 3,
        wasm_frame: 4,
        wasm_to_js_frame: 5,
        wasm_to_js_function_frame: 0,
        js_to_wasm_frame: 6,
        wasm_debug_break_frame: 7,
        stack_switch_frame: 0,
        wasm_exit_frame: 9,
        c_wasm_entry_frame: 8,
        wasm_compile_lazy_frame: 10,
        wasm_liftoff_setup_frame: 0,
        interpreted_frame: 11,
        baseline_frame: 12,
        maglev_frame: 0,
        turbofan_frame: 0,
        stub_frame: 14,
        turbofan_stub_with_context_frame: 0,
        builtin_continuation_frame: 15,
        js_builtin_continuation_frame: 16,
        js_builtin_continuation_with_catch_frame: 17,
        internal_frame: 18,
        construct_frame: 19,
        fast_construct_frame: 0,
        builtin_frame: 20,
        builtin_exit_frame: 21,
        native_frame: 22,
        api_callback_exit_frame: 0,
        irregexp_frame: 0,
        optimized_frame: 13,
    },
    codekind: V8CodeKind {
        mask: 15,
        shift: 0,
        baseline: 11,
        interpreted: 10,
    },
};

// V8 10.8.x offsets (Node.js 19.x - odd version)
pub const V8_10_8_OFFSETS: &V8Offsets = &V8Offsets {
    frame_pointers: V8FramePointers {
        marker: -8,
        function: -16,
        bytecode_offset: -40,
    },
    js_function: V8JSFunction {
        shared: 24,
        code: 48,
    },
    shared_function_info: V8SharedFunctionInfo {
        name_or_scope_info: 16,
        function_data: 8,
        script_or_debug_info: 32,
    },
    code: V8Code {
        instruction_start: 128,    // 0x80
        instruction_size: 40,      // 0x28
        flags: 48,                 // 0x30
        deoptimization_data: 16,   // 0x10
        source_position_table: 24, // 0x18
    },
    script: V8Script {
        name: 16,
        source: 8,
    },
    bytecode_array: V8BytecodeArray {
        source_position_table: 32, // 0x20
    },
    v8_type: V8Type {
        scope_info: 253,           // 0xfd
        shared_function_info: 254, // 0xfe
        js_function_first: 2065,   // 0x811
        js_function_last: 2079,    // 0x81f
        string_first: 0,
        script: 168, // 0xa8
        code: 237,   // 0xed
    },
    v8_fixed: V8Fixed {
        first_nonstring_type: 128,
        string_representation_mask: 0x7,
        seq_string_tag: 0x0,
        cons_string_tag: 0x1,
        thin_string_tag: 0x5,
    },
    scope_info_index: V8ScopeInfoIndex {
        first_vars: 3,
        n_context_locals: 2,
    },
    deopt_data_index: V8DeoptimizationDataIndex {
        inlined_function_count: 1,
        literal_array: 2,
        shared_function_info: 6,
        inlining_positions: 7,
    },
    heap_object: V8HeapObject { map: 0 },
    map: V8Map { instance_type: 12 },
    frame_types: V8FrameTypes {
        entry_frame: 1,
        construct_entry_frame: 2,
        exit_frame: 3,
        wasm_frame: 4,
        wasm_to_js_frame: 5,
        wasm_to_js_function_frame: 0,
        js_to_wasm_frame: 7,
        wasm_debug_break_frame: 8,
        stack_switch_frame: 0,
        wasm_exit_frame: 11,
        c_wasm_entry_frame: 10,
        wasm_compile_lazy_frame: 12,
        wasm_liftoff_setup_frame: 0,
        interpreted_frame: 13,
        baseline_frame: 14,
        maglev_frame: 0,
        turbofan_frame: 0,
        stub_frame: 17,
        turbofan_stub_with_context_frame: 0,
        builtin_continuation_frame: 19,
        js_builtin_continuation_frame: 20,
        js_builtin_continuation_with_catch_frame: 21,
        internal_frame: 22,
        construct_frame: 23,
        fast_construct_frame: 0,
        builtin_frame: 24,
        builtin_exit_frame: 25,
        native_frame: 26,
        api_callback_exit_frame: 0,
        irregexp_frame: 0,
        optimized_frame: 0,
    },
    codekind: V8CodeKind {
        mask: 15,
        shift: 0,
        baseline: 11,
        interpreted: 10,
    },
};

// V8 11.8.x offsets (Node.js 21.x - odd version)
pub const V8_11_8_OFFSETS: &V8Offsets = &V8Offsets {
    frame_pointers: V8FramePointers {
        marker: -8,
        function: -16,
        bytecode_offset: -40,
    },
    js_function: V8JSFunction {
        shared: 32, // 0x20 - Different from V8 11.3!
        code: 24,   // 0x18 - Different from V8 11.3!
    },
    shared_function_info: V8SharedFunctionInfo {
        name_or_scope_info: 16,
        function_data: 8,
        script_or_debug_info: 32,
    },
    code: V8Code {
        instruction_start: 32,     // 0x20 - Different from V8 11.3!
        instruction_size: 44,      // 0x2c - Different from V8 11.3!
        flags: 40,                 // 0x28 - Different from V8 11.3!
        deoptimization_data: 8,    // 0x8
        source_position_table: 16, // 0x10
    },
    script: V8Script {
        name: 16,
        source: 8,
    },
    bytecode_array: V8BytecodeArray {
        source_position_table: 32, // 0x20
    },
    v8_type: V8Type {
        scope_info: 263,           // 0x107 - Different!
        shared_function_info: 264, // 0x108 - Different!
        js_function_first: 2066,   // 0x812
        js_function_last: 2081,    // 0x821
        string_first: 0,
        script: 167, // 0xa7
        code: 246,   // 0xf6 - Different!
    },
    v8_fixed: V8Fixed {
        first_nonstring_type: 128,
        string_representation_mask: 0x7,
        seq_string_tag: 0x0,
        cons_string_tag: 0x1,
        thin_string_tag: 0x5,
    },
    scope_info_index: V8ScopeInfoIndex {
        first_vars: 3,
        n_context_locals: 2,
    },
    deopt_data_index: V8DeoptimizationDataIndex {
        inlined_function_count: 1,
        literal_array: 2,
        shared_function_info: 6,
        inlining_positions: 7,
    },
    heap_object: V8HeapObject { map: 0 },
    map: V8Map { instance_type: 12 },
    frame_types: V8FrameTypes {
        entry_frame: 1,
        construct_entry_frame: 2,
        exit_frame: 3,
        wasm_frame: 4,
        wasm_to_js_frame: 5,
        wasm_to_js_function_frame: 6,
        js_to_wasm_frame: 7,
        wasm_debug_break_frame: 9,
        stack_switch_frame: 8,
        wasm_exit_frame: 11,
        c_wasm_entry_frame: 10,
        wasm_compile_lazy_frame: 0,
        wasm_liftoff_setup_frame: 12,
        interpreted_frame: 13,
        baseline_frame: 14,
        maglev_frame: 15,
        turbofan_frame: 16,
        stub_frame: 17,
        turbofan_stub_with_context_frame: 18,
        builtin_continuation_frame: 19,
        js_builtin_continuation_frame: 20,
        js_builtin_continuation_with_catch_frame: 21,
        internal_frame: 22,
        construct_frame: 23,
        fast_construct_frame: 0,
        builtin_frame: 25,
        builtin_exit_frame: 26,
        native_frame: 28,
        api_callback_exit_frame: 0,
        irregexp_frame: 27,
        optimized_frame: 0,
    },
    codekind: V8CodeKind {
        mask: 15,
        shift: 0,
        baseline: 11,
        interpreted: 10,
    },
};

// V8 12.9.x offsets (Node.js 23.x - odd version)
pub const V8_12_9_OFFSETS: &V8Offsets = &V8Offsets {
    frame_pointers: V8FramePointers {
        marker: -8,
        function: -16,
        bytecode_offset: -40,
    },
    js_function: V8JSFunction {
        shared: 32, // 0x20
        code: 24,   // 0x18
    },
    shared_function_info: V8SharedFunctionInfo {
        name_or_scope_info: 24, // 0x18 - Different!
        function_data: 8,
        script_or_debug_info: 40, // 0x28 - Different!
    },
    code: V8Code {
        instruction_start: 40,     // 0x28
        instruction_size: 52,      // 0x34
        flags: 48,                 // 0x30
        deoptimization_data: 8,    // 0x8
        source_position_table: 16, // 0x10
    },
    script: V8Script {
        name: 16,
        source: 8,
    },
    bytecode_array: V8BytecodeArray {
        source_position_table: 32, // 0x20
    },
    v8_type: V8Type {
        scope_info: 279,           // 0x117 - Different!
        shared_function_info: 281, // 0x119 - Different!
        js_function_first: 2065,   // 0x811 - Different!
        js_function_last: 2081,    // 0x821
        string_first: 0,
        script: 167, // 0xa7
        code: 186,   // 0xba - Very different!
    },
    v8_fixed: V8Fixed {
        first_nonstring_type: 128,
        string_representation_mask: 0x7,
        seq_string_tag: 0x0,
        cons_string_tag: 0x1,
        thin_string_tag: 0x5,
    },
    scope_info_index: V8ScopeInfoIndex {
        first_vars: 5, // 0x5 - CRITICAL CHANGE!
        n_context_locals: 2,
    },
    deopt_data_index: V8DeoptimizationDataIndex {
        inlined_function_count: 1,
        literal_array: 2,
        shared_function_info: 0, // Not found, using wrapper
        inlining_positions: 7,
    },
    heap_object: V8HeapObject { map: 0 },
    map: V8Map { instance_type: 12 },
    frame_types: V8FrameTypes {
        entry_frame: 1,
        construct_entry_frame: 2,
        exit_frame: 3,
        wasm_frame: 4,
        wasm_to_js_frame: 5,
        wasm_to_js_function_frame: 6,
        js_to_wasm_frame: 7,
        wasm_debug_break_frame: 9,
        stack_switch_frame: 8,
        wasm_exit_frame: 11,
        c_wasm_entry_frame: 10,
        wasm_compile_lazy_frame: 0,
        wasm_liftoff_setup_frame: 12,
        interpreted_frame: 13,
        baseline_frame: 14,
        maglev_frame: 15,
        turbofan_frame: 16,
        stub_frame: 17,
        turbofan_stub_with_context_frame: 18,
        builtin_continuation_frame: 19,
        js_builtin_continuation_frame: 20,
        js_builtin_continuation_with_catch_frame: 21,
        internal_frame: 22,
        construct_frame: 23,
        fast_construct_frame: 24,
        builtin_frame: 25,
        builtin_exit_frame: 26,
        native_frame: 29, // 0x1d - Different!
        api_callback_exit_frame: 27,
        irregexp_frame: 28, // Different position
        optimized_frame: 0,
    },
    codekind: V8CodeKind {
        mask: 15,
        shift: 0,
        baseline: 10,   // 0xa - CRITICAL CHANGE!
        interpreted: 9, // 0x9 - CRITICAL CHANGE!
    },
};

#[derive(Default)]
pub struct V8UnwindTable {
    symbolizers: HashMap<u32, V8Symbolizer>, // Per-process symbolizers
    unwind_info_map_fd: i32,
}

impl V8UnwindTable {
    pub unsafe fn new(unwind_info_map_fd: i32) -> Self {
        Self {
            unwind_info_map_fd,
            ..Default::default()
        }
    }

    pub unsafe fn load(&mut self, pid: u32) {
        trace!("load V8 unwind info for process#{pid}");
        let info = match InterpreterInfo::new(pid) {
            Ok(info) => info,
            Err(_e) => {
                trace!("Load failed due to namespace isolation, missing binary access, or unsupported version");
                return;
            }
        };

        // Check version range: only V8 >= 9.0.0 (Node.js >= 16.x) is supported
        // For unsupported versions, skip loading unwind_info_map to allow native stack only
        let req = VersionReq::parse(">=9.0.0").unwrap();
        if !req.matches(&info.v8_version) {
            trace!(
                "Process#{pid} V8 version {} is not supported (need >= 9.0.0), skipping interpreter unwinding",
                info.v8_version
            );
            return;
        }

        // Additional check: ensure V8 version is <= 12.9.x (latest tested)
        // Versions beyond this will use V8 12.9 offsets but log a warning
        if info.v8_version.major > 12 || (info.v8_version.major == 12 && info.v8_version.minor > 9)
        {
            trace!(
                "Process#{pid} V8 version {} is newer than tested versions, using V8 12.9 offsets",
                info.v8_version
            );
        }

        // Register version for FFI lookup
        if let Ok(mut registry) = get_version_registry().lock() {
            registry.insert(pid, info.v8_version.clone());
        }

        // Register as V8 interpreter in the global type registry
        // This enables strict O(1) lookup in is_v8_process()
        crate::register_interpreter(pid, crate::InterpreterType::V8);

        // Create symbolizer for this process
        let offsets = get_offsets_for_v8_version(&info.v8_version);
        let symbolizer = V8Symbolizer::new(pid, *offsets);
        self.symbolizers.insert(pid, symbolizer);

        // Create V8ProcInfo with all offset fields populated
        // Encoding: major * 1000000 + minor * 10000 + patch
        // This handles 3-digit patch numbers (e.g., V8 12.9.202)
        let version = info.v8_version.major as u32 * 1000000
            + info.v8_version.minor as u32 * 10000
            + info.v8_version.patch as u32;
        trace!(
            "Process#{pid} Final V8 version for BPF: {} (encoded: {})",
            info.v8_version,
            version
        );
        let proc_info = V8ProcInfo::from_offsets(&offsets, version);

        // For testing with invalid file descriptors, return early
        if self.unwind_info_map_fd < 0 {
            trace!("skip update V8 proc info for process#{pid} due to invalid file descriptor");
            return;
        }

        if bpf_update_elem(
            self.unwind_info_map_fd,
            &pid as *const u32 as *const c_void,
            &proc_info as *const V8ProcInfo as *const c_void,
            BPF_ANY,
        ) != 0
        {
            warn!(
                "Failed to update v8_unwind_info_map for process#{pid}: errno={}",
                get_errno()
            );
        } else {
        }
    }

    pub unsafe fn unload(&mut self, pid: u32) {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if bpf_delete_elem(self.unwind_info_map_fd, &pid as *const u32 as *const c_void) != 0 {
            // Only log if error is not ENOENT (entry doesn't exist)
            if errno != 2 {
                // ENOENT = 2
            }
        } else {
        }

        // Remove symbolizer and version registration
        self.symbolizers.remove(&pid);
        if let Ok(mut registry) = get_version_registry().lock() {
            registry.remove(&pid);
        }

        // Unregister from global interpreter type registry
        crate::unregister_interpreter(pid);
    }

    /// Get V8 version for a specific process
    pub fn get_process_version(&self, pid: u32) -> Option<Version> {
        if let Ok(registry) = get_version_registry().lock() {
            registry.get(&pid).cloned()
        } else {
            None
        }
    }

    /// Get appropriate V8 offsets for a process
    pub fn get_offsets_for_process(&self, pid: u32) -> V8Offsets {
        *get_offsets_for_pid(pid)
    }

    /// Symbolize V8 frame using metadata from eBPF.
    ///
    /// This is the new interface that uses the v8_symbolizer module.
    pub fn symbolize_frame_with_metadata(
        &mut self,
        pid: u32,
        metadata: &V8FrameMetadata,
    ) -> String {
        if let Some(symbolizer) = self.symbolizers.get_mut(&pid) {
            let frame_info = symbolizer.symbolize_frame(metadata);

            // Format frame info as string for output
            if frame_info.line_number > 0 {
                format!(
                    "{}@{}:{}",
                    frame_info.function_name, frame_info.file_name, frame_info.line_number
                )
            } else {
                format!("{}@{}", frame_info.function_name, frame_info.file_name)
            }
        } else {
            // Fallback if symbolizer not available
            match metadata.frame_type {
                1 => format!("V8:Stub#{}", metadata.bytecode_offset),
                2 => format!("V8:Bytecode@{:x}", metadata.jsfunc_ptr),
                3 | 4 | 5 => format!("V8:Native@{:x}", metadata.code_ptr),
                _ => "V8:Unknown".to_string(),
            }
        }
    }
}

/// Merge V8 interpreter stack with native stack
pub fn merge_stacks(interpreter_trace: &str, native_trace: &str) -> String {
    if interpreter_trace.is_empty() && native_trace.is_empty() {
        return String::new();
    } else if interpreter_trace.is_empty() {
        return native_trace.to_string();
    } else if native_trace.is_empty() {
        return interpreter_trace.to_string();
    }

    // Clean up V8 stack (remove leading semicolon if present)
    let clean_js_trace = if interpreter_trace.starts_with(';') {
        &interpreter_trace[1..]
    } else {
        interpreter_trace
    };

    // Parse and enhance V8 frames with better symbolization
    let enhanced_js_trace = enhance_v8_trace(clean_js_trace);

    // New strategy: Replace Builtins_ and [unknown] frames with JS frames
    replace_builtin_frames_with_js(native_trace, &enhanced_js_trace)
}

/// Replace Builtins_ and [unknown] frames in native stack with JS frames
fn replace_builtin_frames_with_js(native_trace: &str, js_trace: &str) -> String {
    // Split both stacks into frames
    let native_frames: Vec<&str> = native_trace.split(';').filter(|f| !f.is_empty()).collect();
    let js_frames: Vec<&str> = js_trace.split(';').filter(|f| !f.is_empty()).collect();

    if js_frames.is_empty() {
        return native_trace.to_string();
    }

    let mut result_frames: Vec<&str> = Vec::new();
    let mut js_frame_idx = 0;
    let mut last_replacement_idx: Option<usize> = None;

    for (_idx, native_frame) in native_frames.iter().enumerate() {
        // Check if this frame should be replaced
        // FIXME: how to find the frames necessary to be replaced
        let should_replace = native_frame.starts_with("Builtins_")
            || native_frame.starts_with("[unknown]")
            || native_frame.contains("Builtins_JSEntry")
            || native_frame.contains("V8::")
            || native_frame.contains("V8::EntryFrame")
            || (native_frame.starts_with("[")
                && native_frame.contains("node")
                && native_frame.ends_with("]"));

        if should_replace && js_frame_idx < js_frames.len() {
            // Replace with JS frame
            result_frames.push(js_frames[js_frame_idx]);
            last_replacement_idx = Some(result_frames.len() - 1);
            js_frame_idx += 1;
        } else {
            // Before keeping this native frame, check if we need to insert remaining JS frames
            // Only insert if: 1) we had replacements before, 2) we have remaining JS frames, 3) we haven't inserted yet
            if last_replacement_idx.is_some() && js_frame_idx < js_frames.len() {
                // Insert all remaining JS frames right after the last replacement
                while js_frame_idx < js_frames.len() {
                    result_frames.push(js_frames[js_frame_idx]);
                    js_frame_idx += 1;
                }
                // Mark that we've inserted, so we don't insert again
                last_replacement_idx = None;
            }

            // Keep native frame
            result_frames.push(native_frame);
        }
    }

    // If we finished with replacements and still have remaining JS frames, append them
    if js_frame_idx < js_frames.len() {
        while js_frame_idx < js_frames.len() {
            result_frames.push(js_frames[js_frame_idx]);
            js_frame_idx += 1;
        }
    }

    let result = result_frames.join(";");
    result
}

/// Enhance V8 trace with better symbolization
fn enhance_v8_trace(trace: &str) -> String {
    if trace.is_empty() {
        return trace.to_string();
    }

    // Split frames and enhance each one
    let frames: Vec<&str> = trace.split(';').collect();

    let enhanced_frames: Vec<String> = frames
        .iter()
        .enumerate()
        .map(|(_idx, frame)| {
            let enhanced = enhance_single_v8_frame(frame);
            if enhanced != *frame {}
            enhanced
        })
        .collect();

    let result = enhanced_frames.join(";");
    result
}

/// Enhance a single V8 frame with better symbolization
fn enhance_single_v8_frame(frame: &str) -> String {
    // Basic frame enhancement - detect frame types and add context
    if frame.starts_with("V8Stub") {
        // This is a stub frame from our eBPF code
        format!("{} [stub]", frame)
    } else if frame.contains("@") && frame.contains("x") {
        // This looks like an address-based frame
        if frame.contains("SFI@") {
            format!("{} [interpreted]", frame)
        } else if frame.contains("Code@") {
            format!("{} [jit]", frame)
        } else {
            frame.to_string()
        }
    } else {
        // Assume it's already a symbolized frame
        frame.to_string()
    }
}

pub fn get_offsets_for_v8_version(version: &Version) -> &'static V8Offsets {
    // Match by (major, minor) for finer-grained version support
    // V8 uses minor version ranges:
    // - Even Node.js versions: minor 0-5 (e.g., 9.4, 10.2, 11.3, 12.4)
    // - Odd Node.js versions: minor 6-9 (e.g., 9.6, 10.8, 11.8, 12.9)
    match (version.major, version.minor) {
        // V8 9.x variants
        (9, 6..=9) => V8_9_6_OFFSETS, // Node.js 17.x (odd) - V8 9.6.x
        (9, 0..=5) => V8_9_OFFSETS,   // Node.js 16.x (even) - V8 9.4.x

        // V8 10.x variants
        (10, 8..=9) => V8_10_8_OFFSETS, // Node.js 19.x (odd) - V8 10.8.x
        (10, 0..=7) => V8_10_OFFSETS,   // Node.js 18.x (even) - V8 10.2.x

        // V8 11.x variants
        (11, 8..=9) => V8_11_8_OFFSETS, // Node.js 21.x (odd) - V8 11.8.x
        (11, 0..=7) => V8_11_OFFSETS,   // Node.js 20.x (even) - V8 11.3.x

        // V8 12.x variants
        (12, 9) => V8_12_9_OFFSETS,   // Node.js 23.x (odd) - V8 12.9.x
        (12, 0..=8) => V8_12_OFFSETS, // Node.js 22.x (even) - V8 12.4.x

        // Future versions: use latest
        (13.., _) => V8_12_9_OFFSETS, // Use V8 12.9 for future versions

        // Older versions: default to V8 9.x
        _ => V8_9_OFFSETS,
    }
}

/// C FFI function to detect if a process is running Node.js/V8
///
/// TWO-PHASE DETECTION:
/// 1. Fast path: Check if already registered (O(1), ~50ns)
///    - If registered, we know it's V8 (validated via ELF parsing during load)
/// 2. Fallback: Lightweight filename check (~10μs)
///    - For new/unregistered processes
///    - After this returns true, v8_unwind_table_load() will:
///      a) Do full ELF validation (V8 version symbols, version check)
///      b) Register to global registry if validation passes
///    - Future calls use fast path
///
/// This ensures:
/// - Strict validation: Only ELF-validated processes stay registered
/// - No chicken-egg problem: Initial detection works via filename
/// - High performance: O(1) lookup for hot paths
#[no_mangle]
pub unsafe extern "C" fn is_v8_process(pid: u32) -> bool {
    // Fast path: O(1) registry lookup for already-loaded processes
    if crate::is_registered_as(pid, crate::InterpreterType::V8) {
        return true;
    }

    // Fallback: Lightweight filename check for new processes
    // This allows v8_unwind_table_load() to be called, which does strict ELF validation
    if let Ok(exe_path) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
        if let Some(filename) = exe_path.file_name() {
            if let Some(name) = filename.to_str() {
                return name == "node"
                    || name.starts_with("node")
                    || name == "nodejs"
                    || name.contains("electron");
            }
        }
    }

    // Additional check via command line
    if let Ok(cmdline) = std::fs::read_to_string(format!("/proc/{}/cmdline", pid)) {
        let args: Vec<&str> = cmdline.split('\0').collect();
        if let Some(first_arg) = args.first() {
            return first_arg.contains("node") || first_arg.contains("electron");
        }
    }

    false
}

/// C FFI function to merge V8 interpreter and native stacks
#[no_mangle]
pub unsafe extern "C" fn merge_v8_stacks(
    trace_str: *mut std::ffi::c_void,
    len: usize,
    i_trace: *const std::ffi::c_void,
    u_trace: *const std::ffi::c_void,
) -> usize {
    if i_trace.is_null() || u_trace.is_null() || trace_str.is_null() {
        return 0;
    }

    let Ok(i_trace) = std::ffi::CStr::from_ptr(i_trace as *const libc::c_char).to_str() else {
        return 0;
    };
    let Ok(u_trace) = std::ffi::CStr::from_ptr(u_trace as *const libc::c_char).to_str() else {
        return 0;
    };

    let merged = merge_stacks(i_trace, u_trace);
    let merged_bytes = merged.as_bytes();
    let trace_len = merged_bytes.len().min(len - 1);

    if trace_len > 0 {
        std::ptr::copy_nonoverlapping(merged_bytes.as_ptr(), trace_str as *mut u8, trace_len);
        *(trace_str as *mut u8).add(trace_len) = 0; // null terminate
    }
    trace_len
}

// Re-export resolve_v8_frame so cbindgen can find it
pub use symbolizer::resolve_v8_frame;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration_tests;
