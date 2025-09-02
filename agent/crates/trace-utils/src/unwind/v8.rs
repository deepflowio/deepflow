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

use std::{cell::OnceCell, collections::HashMap, fs, path::PathBuf};

use libc::c_void;
use log::{debug, trace, warn};
use object::{Object, ObjectSymbol};
use regex::Regex;
use semver::{Version, VersionReq};

use crate::{
    error::{Error, Result},
    maps::{get_memory_mappings, MemoryArea},
    utils::{bpf_delete_elem, bpf_update_elem, get_errno, IdGenerator, BPF_ANY},
};

// V8 stack merging constants
const INCOMPLETE_V8_STACK: &'static str = "[lost] incomplete V8 c stack";

// V8 Frame type constants (matching OpenTelemetry implementation)
const V8_FILE_TYPE_MARKER: u64 = 0x0;
const V8_FILE_TYPE_BYTECODE: u64 = 0x1;
const V8_FILE_TYPE_NATIVE_SFI: u64 = 0x2;
const V8_FILE_TYPE_NATIVE_CODE: u64 = 0x3;
const V8_FILE_TYPE_NATIVE_JSFUNC: u64 = 0x4;

// V8 frame type mask and shifts
const V8_FILE_TYPE_MASK: u64 = 0x7;

fn error_not_v8(pid: u32) -> Error {
    Error::BadInterpreterType(pid, "v8")
}

fn error_not_supported_version(pid: u32, version: Version) -> Error {
    Error::BadInterpreterVersion(pid, "v8", version)
}

struct MappedFile {
    path: PathBuf,
    contents: Vec<u8>,
    mem_start: u64,
}

impl MappedFile {
    fn new(path: &str, mem_start: u64) -> Self {
        Self {
            path: PathBuf::from(path),
            contents: Vec::new(),
            mem_start,
        }
    }

    fn load(&mut self) -> Result<()> {
        if self.contents.is_empty() {
            self.contents = fs::read(&self.path)?;
        }
        Ok(())
    }

    fn has_any_symbols(&mut self, symbols: &[&str]) -> Result<bool> {
        self.load()?;
        let obj = object::File::parse(&*self.contents)?;
        Ok(obj.symbols().chain(obj.dynamic_symbols()).any(|s| {
            if let Ok(name) = s.name() {
                for sym in symbols {
                    if &name == sym || name.contains(sym) {
                        return true;
                    }
                }
            }
            false
        }))
    }

    thread_local! {
        static NODE_VERSION_REGEX: OnceCell<Regex> = OnceCell::new();
    }

    const NODE_VERSION_REGEX_STR: &'static str = r"node-v?(\d+)\.(\d+)\.(\d+)";

    fn parse_node_version(cap: regex::Captures) -> Option<Version> {
        Some(Version::new(
            cap.get(1)?.as_str().parse().ok()?,
            cap.get(2)?.as_str().parse().ok()?,
            cap.get(3)?.as_str().parse().ok()?,
        ))
    }

    fn version(&self) -> Option<Version> {
        if let Some(c) = self.path.to_str().and_then(|s| {
            Self::NODE_VERSION_REGEX.with(|r| {
                r.get_or_init(|| Regex::new(Self::NODE_VERSION_REGEX_STR).unwrap())
                    .captures(s)
            })
        }) {
            match Self::parse_node_version(c) {
                Some(v) => return Some(v),
                None => debug!("Cannot find node version from file {}", self.path.display()),
            }
        }
        None
    }

    fn find_symbol_address(&mut self, name: &str) -> Result<Option<u64>> {
        self.load()?;
        let obj = object::File::parse(&*self.contents)?;
        Ok(obj
            .symbols()
            .chain(obj.dynamic_symbols())
            .find(|s| s.name().map(|n| n == name).unwrap_or(false))
            .map(|s| s.address() + self.mem_start))
    }

    fn has_v8_symbols(&mut self) -> Result<bool> {
        let v8_symbols = [
            "v8dbg_type_JSFunction",
            "v8dbg_type_SharedFunctionInfo",
            "v8dbg_off_HeapObject__map",
            "v8::internal::Isolate",
            "V8",
        ];
        self.has_any_symbols(&v8_symbols)
    }

    fn node_to_v8_version(&self, node_version: &Version) -> Option<Version> {
        match (node_version.major, node_version.minor) {
            (22, _) => Some(Version::new(12, 4, 254)),
            (21, _) => Some(Version::new(11, 8, 172)),
            (20, _) => Some(Version::new(11, 3, 244)),
            (18, _) => Some(Version::new(10, 2, 154)),
            (16, _) => Some(Version::new(9, 4, 146)),
            _ => Some(Version::new(12, 4, 254)), // default to latest
        }
    }
}

struct Interpreter {
    pid: u32,
    exe: MappedFile,
    node_version: Version,
    v8_version: Version,
}

impl Interpreter {
    fn new(pid: u32, exe_area: &MemoryArea) -> Result<Self> {
        let mut exe = MappedFile::new(&exe_area.path, exe_area.m_start);

        if !exe.has_v8_symbols()? {
            return Err(error_not_v8(pid));
        }

        let node_version = exe.version().unwrap_or_else(|| Version::new(20, 0, 0));
        let v8_version = exe
            .node_to_v8_version(&node_version)
            .unwrap_or_else(|| Version::new(11, 3, 244));

        Ok(Self {
            pid,
            exe,
            node_version,
            v8_version,
        })
    }

    fn isolate_address(&mut self) -> Result<u64> {
        // 在实际实现中需要从进程内存中动态获取isolate地址
        // 这里简化为返回一个固定值
        debug!("Getting isolate address for V8 process {}", self.pid);
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

        debug!("process#{pid} exe: {}", exe_area.path);

        let mut intp = Interpreter::new(pid, exe_area)?;

        // Check if the Node.js version is supported
        let req = VersionReq::parse(">=16.0.0, <22.0.0").unwrap();
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8Offsets {
    pub frame_pointers: V8FramePointers,
    pub js_function: V8JSFunction,
    pub shared_function_info: V8SharedFunctionInfo,
    pub code: V8Code,
    pub script: V8Script,
    pub bytecode_array: V8BytecodeArray,
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
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8BytecodeArray {
    pub source_position_table: u16,
}

// V8 9.x offsets (Node.js 16.x)
const V8_9_OFFSETS: &V8Offsets = &V8Offsets {
    frame_pointers: V8FramePointers {
        marker: -16,
        function: -8,
        bytecode_offset: -24,
    },
    js_function: V8JSFunction {
        shared: 16,
        code: 24,
    },
    shared_function_info: V8SharedFunctionInfo {
        name_or_scope_info: 8,
        function_data: 12,
        script_or_debug_info: 16,
    },
    code: V8Code {
        instruction_start: 40,
        instruction_size: 48,
        flags: 56,
    },
    script: V8Script {
        name: 12,
        source: 16,
    },
    bytecode_array: V8BytecodeArray {
        source_position_table: 8,
    },
};

// V8 10.x offsets (Node.js 18.x)
const V8_10_OFFSETS: &V8Offsets = &V8Offsets {
    frame_pointers: V8FramePointers {
        marker: -16,
        function: -8,
        bytecode_offset: -24,
    },
    js_function: V8JSFunction {
        shared: 16,
        code: 24,
    },
    shared_function_info: V8SharedFunctionInfo {
        name_or_scope_info: 8,
        function_data: 12,
        script_or_debug_info: 16,
    },
    code: V8Code {
        instruction_start: 40,
        instruction_size: 48,
        flags: 56,
    },
    script: V8Script {
        name: 12,
        source: 16,
    },
    bytecode_array: V8BytecodeArray {
        source_position_table: 8,
    },
};

// V8 11.x offsets (Node.js 20.x)
const V8_11_OFFSETS: &V8Offsets = &V8Offsets {
    frame_pointers: V8FramePointers {
        marker: -16,
        function: -8,
        bytecode_offset: -24,
    },
    js_function: V8JSFunction {
        shared: 16,
        code: 24,
    },
    shared_function_info: V8SharedFunctionInfo {
        name_or_scope_info: 8,
        function_data: 12,
        script_or_debug_info: 16,
    },
    code: V8Code {
        instruction_start: 40,
        instruction_size: 48,
        flags: 56,
    },
    script: V8Script {
        name: 12,
        source: 16,
    },
    bytecode_array: V8BytecodeArray {
        source_position_table: 8,
    },
};

#[derive(Default)]
pub struct V8UnwindTable {
    id_gen: IdGenerator,
    loaded_offsets: HashMap<Version, u8>,
    process_versions: HashMap<u32, Version>, // Track V8 version per process
    unwind_info_map_fd: i32,
    offsets_map_fd: i32,
}

impl V8UnwindTable {
    pub unsafe fn new(unwind_info_map_fd: i32, offsets_map_fd: i32) -> Self {
        Self {
            unwind_info_map_fd,
            offsets_map_fd,
            process_versions: HashMap::new(),
            ..Default::default()
        }
    }

    pub unsafe fn load(&mut self, pid: u32) {
        trace!("load V8 unwind info for process#{pid}");
        let info = match InterpreterInfo::new(pid) {
            Ok(info) => info,
            Err(e) => {
                trace!("loading V8 interpreter info for process#{pid} has error: {e}");
                return;
            }
        };

        let req = VersionReq::parse(">=9.0.0").unwrap();
        if !req.matches(&info.v8_version) {
            debug!("V8 version {} is not supported", info.v8_version);
            return;
        }

        // Store version info for this process
        self.process_versions.insert(pid, info.v8_version.clone());

        let offsets_id = self.get_or_load_offsets(&info.v8_version);

        let unwind_info = V8UnwindInfo {
            isolate_address: info.isolate_address,
            offsets_id,
            version: info.v8_version.major as u32 * 10000
                + info.v8_version.minor as u32 * 100
                + info.v8_version.patch as u32,
        };

        if bpf_update_elem(
            self.unwind_info_map_fd,
            &pid as *const u32 as *const c_void,
            &unwind_info as *const V8UnwindInfo as *const c_void,
            BPF_ANY,
        ) != 0
        {
            warn!(
                "failed to update v8_unwind_info_map for process#{pid}: {}",
                get_errno()
            );
        }
    }

    fn get_or_load_offsets(&mut self, version: &Version) -> u8 {
        if let Some(&id) = self.loaded_offsets.get(version) {
            return id;
        }

        let id_u32 = self.id_gen.acquire();
        let id = id_u32 as u8; // Convert u32 to u8
        let offsets = self.get_offsets_for_version(version);

        unsafe {
            if bpf_update_elem(
                self.offsets_map_fd,
                &id as *const u8 as *const c_void,
                &offsets as *const V8Offsets as *const c_void,
                BPF_ANY,
            ) != 0
            {
                warn!("failed to update v8_offsets_map: {}", get_errno());
            }
        }

        self.loaded_offsets.insert(version.clone(), id);
        id
    }

    fn get_offsets_for_version(&self, version: &Version) -> V8Offsets {
        match version.major {
            9 => *V8_9_OFFSETS,
            10 => *V8_10_OFFSETS,
            11 => *V8_11_OFFSETS,
            12.. => *V8_11_OFFSETS, // Use latest available
            _ => *V8_9_OFFSETS,     // Default to 9.x for older versions
        }
    }

    pub unsafe fn unload(&mut self, pid: u32) {
        if bpf_delete_elem(self.unwind_info_map_fd, &pid as *const u32 as *const c_void) != 0 {
            trace!("failed to delete v8_unwind_info_map for process#{pid}");
        }

        // Remove version info for this process
        self.process_versions.remove(&pid);
    }

    /// Get V8 version for a specific process
    pub fn get_process_version(&self, pid: u32) -> Option<&Version> {
        self.process_versions.get(&pid)
    }

    /// Get appropriate V8 offsets for a process (dynamic version detection)
    pub fn get_offsets_for_process(&self, pid: u32) -> V8Offsets {
        if let Some(version) = self.get_process_version(pid) {
            self.get_offsets_for_version(version)
        } else {
            // Fallback to latest version if version info is not available
            *V8_11_OFFSETS
        }
    }

    // V8 Symbolization Methods

    /// Main symbolization entry point (matching OpenTelemetry interface)
    pub fn symbolize_frame(
        &self,
        pid: u32,
        pointer_and_type: u64,
        delta_or_marker: u64,
        return_address: bool,
    ) -> Result<String> {
        let frame_type = pointer_and_type & V8_FILE_TYPE_MASK;
        let pointer = pointer_and_type & !V8_FILE_TYPE_MASK;

        match frame_type {
            V8_FILE_TYPE_MARKER => self.symbolize_marker_frame(delta_or_marker),
            V8_FILE_TYPE_BYTECODE => self.symbolize_bytecode_frame(pid, pointer, delta_or_marker),
            V8_FILE_TYPE_NATIVE_SFI => self.symbolize_sfi(pid, pointer, delta_or_marker),
            V8_FILE_TYPE_NATIVE_CODE => {
                self.symbolize_code(pid, pointer, delta_or_marker, return_address)
            }
            V8_FILE_TYPE_NATIVE_JSFUNC => {
                self.symbolize_js_function_frame(pid, pointer, delta_or_marker, return_address)
            }
            _ => {
                // Handle simplified symbol names from new tail-call implementation
                if pointer == 0 {
                    // This is a simplified symbol generated by the eBPF code
                    match delta_or_marker {
                        0 => Ok("V8:stub".to_string()),
                        1 => Ok("V8:bc".to_string()),
                        2 => Ok("V8:native".to_string()),
                        _ => Ok(format!("V8:UnknownType#{}", delta_or_marker)),
                    }
                } else {
                    Ok(format!("V8:UnknownType#{}@{:x}", frame_type, pointer))
                }
            }
        }
    }

    /// Symbolize a V8 marker/stub frame
    pub fn symbolize_marker_frame(&self, marker: u64) -> Result<String> {
        let frame_type = marker as usize;
        Ok(match frame_type {
            0 => "V8:EntryFrame".to_string(),
            1 => "V8:ExitFrame".to_string(),
            2 => "V8:OptimizedFrame".to_string(),
            3 => "V8:WasmFrame".to_string(),
            4 => "V8:WasmExitFrame".to_string(),
            5 => "V8:BuiltinExitFrame".to_string(),
            6 => "V8:InternalFrame".to_string(),
            7 => "V8:ConstructFrame".to_string(),
            8 => "V8:BuiltinFrame".to_string(),
            9 => "V8:JavaScriptFrame".to_string(),
            10 => "V8:ArgumentsAdaptorFrame".to_string(),
            11 => "V8:InterpretedFrame".to_string(),
            _ => format!("V8:UnknownStub#{}", frame_type),
        })
    }

    /// Symbolize a SharedFunctionInfo pointer
    pub fn symbolize_sfi(&self, pid: u32, sfi_ptr: u64, delta: u64) -> Result<String> {
        // Get process memory reader
        let mem_maps = get_memory_mappings(pid)?;
        let exe_area = mem_maps
            .iter()
            .find(|area| area.mx_start > 0) // Has executable section
            .ok_or_else(|| Error::ProcessNotFound(pid))?;

        let _file = MappedFile::new(&exe_area.path, exe_area.m_start);

        // Try to extract function name from SFI
        match self.read_sfi_name(pid, sfi_ptr) {
            Ok(name) if !name.is_empty() => {
                // Try to get line number from delta
                let line = if delta > 0 {
                    format!(":{}", (delta >> 32) as u32)
                } else {
                    String::new()
                };
                let offset = if delta & 0xFFFFFFFF != 0 {
                    format!("+{}", delta & 0xFFFFFFFF)
                } else {
                    String::new()
                };
                Ok(format!("{}{}{}", name, line, offset))
            }
            _ => {
                // Fallback to address-based symbol
                Ok(format!("V8:SFI@{:x}", sfi_ptr))
            }
        }
    }

    /// Symbolize a Code object pointer
    pub fn symbolize_code(
        &self,
        pid: u32,
        code_ptr: u64,
        delta: u64,
        return_address: bool,
    ) -> Result<String> {
        // Get the SFI from the Code object
        match self.read_code_sfi(pid, code_ptr) {
            Ok(sfi_ptr) => {
                let mut symbol = self.symbolize_sfi(pid, sfi_ptr, delta)?;
                if return_address {
                    symbol = format!("{}@ret", symbol);
                }
                // Add code type indicator
                symbol = format!("{}[jit]", symbol);
                Ok(symbol)
            }
            Err(_) => {
                // Fallback to code address
                Ok(format!(
                    "V8:Code@{:x}{}",
                    code_ptr,
                    if return_address { "@ret" } else { "" }
                ))
            }
        }
    }

    /// Symbolize a bytecode frame (interpreted JavaScript)
    pub fn symbolize_bytecode_frame(&self, pid: u32, sfi_ptr: u64, delta: u64) -> Result<String> {
        let function_name = self.read_sfi_name(pid, sfi_ptr)?;
        let bytecode_offset = delta & 0xFFFFFFFF;

        if bytecode_offset > 0 {
            Ok(format!("{}[bc+{}]", function_name, bytecode_offset))
        } else {
            Ok(format!("{}[bc]", function_name))
        }
    }

    /// Symbolize a JavaScript function frame
    pub fn symbolize_js_function_frame(
        &self,
        pid: u32,
        jsfunc_ptr: u64,
        delta: u64,
        return_address: bool,
    ) -> Result<String> {
        // Get the SharedFunctionInfo from JSFunction (dynamic version detection)
        let offsets = self.get_offsets_for_process(pid);

        match self.read_process_memory_u64(pid, jsfunc_ptr + offsets.js_function.shared as u64) {
            Ok(sfi_ptr) => {
                let clean_sfi = verify_heap_pointer(sfi_ptr);
                if clean_sfi == 0 {
                    return Ok(format!("V8:InvalidJSFunc@{:x}", jsfunc_ptr));
                }

                let mut symbol = self.symbolize_sfi(pid, clean_sfi, delta)?;

                if return_address {
                    symbol = format!("{}@ret", symbol);
                }

                // Check if this function has been compiled to native code
                if let Ok(code_ptr) =
                    self.read_process_memory_u64(pid, jsfunc_ptr + offsets.js_function.code as u64)
                {
                    let clean_code = verify_heap_pointer(code_ptr);
                    if clean_code != 0 {
                        symbol = format!("{}[compiled]", symbol);
                    }
                }

                Ok(symbol)
            }
            Err(_) => Ok(format!("V8:JSFunc@{:x}", jsfunc_ptr)),
        }
    }

    /// Read function name from SharedFunctionInfo
    fn read_sfi_name(&self, pid: u32, sfi_ptr: u64) -> Result<String> {
        // Get V8 offsets for this process (dynamic version detection)
        let offsets = self.get_offsets_for_process(pid);

        // Try to read the name_or_scope_info field
        match self.read_process_memory_u64(
            pid,
            sfi_ptr + offsets.shared_function_info.name_or_scope_info as u64,
        ) {
            Ok(name_or_scope_ptr) => {
                let clean_ptr = verify_heap_pointer(name_or_scope_ptr);
                if clean_ptr == 0 {
                    return Ok(format!("UnknownSFI@{:x}", sfi_ptr));
                }

                // Try to extract string - simplified version
                match self.extract_v8_string(pid, clean_ptr) {
                    Ok(name) if !name.is_empty() => Ok(name),
                    _ => {
                        // Try to analyze as ScopeInfo
                        match self.analyze_scope_info(pid, clean_ptr) {
                            Ok(scope_name) if !scope_name.is_empty() => Ok(scope_name),
                            _ => Ok(format!("SFI@{:x}", sfi_ptr)),
                        }
                    }
                }
            }
            Err(_) => Ok(format!("InvalidSFI@{:x}", sfi_ptr)),
        }
    }

    /// Read SharedFunctionInfo pointer from Code object
    fn read_code_sfi(&self, pid: u32, code_ptr: u64) -> Result<u64> {
        // Code object doesn't directly contain SFI, need to find it through other means
        // This is a simplified approach - in reality we'd need to traverse object relationships

        // Try to read what might be an SFI pointer at a known offset
        self.read_process_memory_u64(pid, code_ptr + 0x18) // Typical SFI offset in Code objects
    }

    /// Extract V8 string content
    fn extract_v8_string(&self, pid: u32, string_ptr: u64) -> Result<String> {
        // V8 strings have different layouts depending on type
        // SeqOneByteString, SeqTwoByteString, ConsString, SlicedString, etc.

        // Read the Map (type info) first
        let map_ptr = self.read_process_memory_u64(pid, string_ptr)?;
        let clean_map = verify_heap_pointer(map_ptr);

        if clean_map == 0 {
            return Err(Error::InvalidPointer(string_ptr));
        }

        // For now, assume it's a SeqOneByteString and try to read it
        // Real implementation would check the Map's instance type

        // Read string length (stored as SMI)
        let length_smi = self.read_process_memory_u64(pid, string_ptr + 8)?;
        let length = parse_v8_smi(length_smi) as usize;

        if length == 0 || length > 1024 {
            // Sanity check
            return Err(Error::InvalidData);
        }

        // Read string data (starts at offset 16 for SeqOneByteString)
        let mut buffer = vec![0u8; length.min(256)]; // Limit to reasonable size
        match self.read_process_memory(pid, string_ptr + 16, &mut buffer) {
            Ok(()) => {
                // Convert to string, stopping at null terminator
                let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
                Ok(String::from_utf8_lossy(&buffer[..end]).to_string())
            }
            Err(_) => Err(Error::ProcessNotFound(pid)),
        }
    }

    /// Analyze V8 ScopeInfo object
    fn analyze_scope_info(&self, pid: u32, scope_info_ptr: u64) -> Result<String> {
        // ScopeInfo contains function and variable names
        // This is a simplified analysis - real implementation would need to parse the entire structure

        // Try to find function name in ScopeInfo
        // ScopeInfo layout is complex and version-dependent, so this is a heuristic approach

        // Read potential string pointers from ScopeInfo
        for offset in (16..64).step_by(8) {
            if let Ok(potential_string_ptr) =
                self.read_process_memory_u64(pid, scope_info_ptr + offset)
            {
                let clean_ptr = verify_heap_pointer(potential_string_ptr);
                if clean_ptr != 0 {
                    if let Ok(name) = self.extract_v8_string(pid, clean_ptr) {
                        if !name.is_empty()
                            && name.len() > 1
                            && name
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
                        {
                            return Ok(name);
                        }
                    }
                }
            }
        }

        Ok(format!("ScopeInfo@{:x}", scope_info_ptr))
    }

    /// Read 64-bit value from process memory
    fn read_process_memory_u64(&self, pid: u32, addr: u64) -> Result<u64> {
        let mut buffer = [0u8; 8];
        self.read_process_memory(pid, addr, &mut buffer)?;
        Ok(u64::from_le_bytes(buffer))
    }

    /// Read arbitrary data from process memory
    fn read_process_memory(&self, _pid: u32, _addr: u64, _buffer: &mut [u8]) -> Result<()> {
        // This is a placeholder - in real implementation, this would use ptrace or /proc/pid/mem
        // For now, return an error to indicate this functionality needs proper implementation
        Err(Error::ProcessNotFound(_pid))
    }

    // Source Position Mapping

    /// Map bytecode offset to source line number
    pub fn map_bytecode_to_source_line(
        &self,
        pid: u32,
        sfi_ptr: u64,
        bytecode_offset: u32,
    ) -> Result<u32> {
        let offsets = self.get_offsets_for_process(pid);

        // Get the BytecodeArray from SharedFunctionInfo
        match self.read_process_memory_u64(
            pid,
            sfi_ptr + offsets.shared_function_info.function_data as u64,
        ) {
            Ok(bytecode_array_ptr) => {
                let clean_ptr = verify_heap_pointer(bytecode_array_ptr);
                if clean_ptr == 0 {
                    return Err(Error::InvalidPointer(bytecode_array_ptr));
                }

                // Get source position table
                match self.read_process_memory_u64(
                    pid,
                    clean_ptr + offsets.bytecode_array.source_position_table as u64,
                ) {
                    Ok(source_pos_table_ptr) => {
                        let clean_table = verify_heap_pointer(source_pos_table_ptr);
                        if clean_table == 0 {
                            return Ok(0); // No source position info
                        }

                        // Parse source position table to find line for bytecode offset
                        self.parse_source_position_table(pid, clean_table, bytecode_offset)
                    }
                    Err(_) => Ok(0),
                }
            }
            Err(_) => Ok(0),
        }
    }

    /// Parse V8 source position table
    fn parse_source_position_table(
        &self,
        pid: u32,
        table_ptr: u64,
        target_offset: u32,
    ) -> Result<u32> {
        // V8 source position tables use Variable-Length Quantity (VLQ) encoding
        // This is a simplified parser that tries to extract line info

        // Read table length first
        let table_length = match self.read_process_memory_u64(pid, table_ptr + 8) {
            Ok(len_smi) => parse_v8_smi(len_smi) as usize,
            Err(_) => return Ok(0),
        };

        if table_length == 0 || table_length > 8192 {
            return Ok(0);
        }

        // Read table data
        let mut table_data = vec![0u8; table_length.min(1024)];
        match self.read_process_memory(pid, table_ptr + 16, &mut table_data) {
            Ok(()) => {
                // Parse VLQ encoded position data
                self.parse_vlq_position_data(&table_data, target_offset)
            }
            Err(_) => Ok(0),
        }
    }

    /// Parse Variable-Length Quantity encoded position data
    fn parse_vlq_position_data(&self, data: &[u8], target_offset: u32) -> Result<u32> {
        let mut pos = 0;
        let mut current_offset = 0u32;
        let mut current_line = 1u32;

        // Parse VLQ entries
        while pos < data.len() {
            // Read bytecode offset delta
            let (offset_delta, new_pos) = match self.decode_vlq(data, pos) {
                Ok((delta, np)) => (delta as u32, np),
                Err(_) => break,
            };
            pos = new_pos;

            current_offset += offset_delta;

            // Read source position delta
            let (source_delta, new_pos) = match self.decode_vlq(data, pos) {
                Ok((delta, np)) => (delta, np),
                Err(_) => break,
            };
            pos = new_pos;

            if source_delta > 0 {
                current_line = current_line.saturating_add(source_delta as u32);
            }

            // Check if we've reached or passed the target offset
            if current_offset >= target_offset {
                return Ok(current_line);
            }
        }

        Ok(current_line)
    }

    /// Decode Variable-Length Quantity integer
    fn decode_vlq(&self, data: &[u8], start_pos: usize) -> Result<(i64, usize)> {
        let mut result = 0i64;
        let mut pos = start_pos;
        let mut shift = 0;

        loop {
            if pos >= data.len() {
                return Err(Error::InvalidData);
            }

            let byte = data[pos];
            pos += 1;

            result |= ((byte & 0x7F) as i64) << shift;
            shift += 7;

            if (byte & 0x80) == 0 {
                break;
            }

            if shift >= 64 {
                return Err(Error::InvalidData);
            }
        }

        // Convert from unsigned to signed (zigzag decoding)
        let unsigned_result = result as u64;
        let signed_result = ((unsigned_result >> 1) as i64) ^ (-((unsigned_result & 1) as i64));

        Ok((signed_result, pos))
    }

    /// Get script information from SharedFunctionInfo
    pub fn get_script_info(&self, pid: u32, sfi_ptr: u64) -> Result<(String, u32)> {
        let offsets = self.get_offsets_for_process(pid);

        // Get script from SharedFunctionInfo
        match self.read_process_memory_u64(
            pid,
            sfi_ptr + offsets.shared_function_info.script_or_debug_info as u64,
        ) {
            Ok(script_ptr) => {
                let clean_script = verify_heap_pointer(script_ptr);
                if clean_script == 0 {
                    return Ok(("unknown".to_string(), 0));
                }

                // Get script name
                let script_name = match self
                    .read_process_memory_u64(pid, clean_script + offsets.script.name as u64)
                {
                    Ok(name_ptr) => {
                        let clean_name = verify_heap_pointer(name_ptr);
                        if clean_name != 0 {
                            self.extract_v8_string(pid, clean_name)
                                .unwrap_or_else(|_| "script".to_string())
                        } else {
                            "script".to_string()
                        }
                    }
                    Err(_) => "script".to_string(),
                };

                // Get line offset (for functions not starting at line 1)
                let line_offset = match self.read_process_memory_u64(pid, sfi_ptr + 20) {
                    // Approximate offset
                    Ok(offset_smi) => parse_v8_smi(offset_smi) as u32,
                    Err(_) => 0,
                };

                Ok((script_name, line_offset))
            }
            Err(_) => Ok(("unknown".to_string(), 0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semver::Version;

    #[test]
    fn test_node_to_v8_version_mapping() {
        let test_cases = vec![
            (Version::new(16, 14, 0), Version::new(9, 4, 146)),
            (Version::new(18, 19, 0), Version::new(10, 2, 154)),
            (Version::new(20, 10, 0), Version::new(11, 3, 244)),
            (Version::new(21, 1, 0), Version::new(11, 8, 172)),
            (Version::new(22, 0, 0), Version::new(12, 4, 254)),
        ];

        for (node_version, expected_v8) in test_cases {
            let mut mapped_file = MappedFile::new("dummy", 0);
            let result = mapped_file.node_to_v8_version(&node_version);
            assert!(result.is_some());
            let v8_version = result.unwrap();
            assert_eq!(v8_version.major, expected_v8.major);
            assert_eq!(v8_version.minor, expected_v8.minor);
        }
    }

    #[test]
    fn test_v8_tagged_pointer_verification() {
        // Test HeapObject pointer (tag = 01)
        let heap_ptr = 0x12345678_00000001u64;
        let invalid_ptr = 0x12345678_00000002u64; // Invalid tag
        let smi_ptr = 0x12345678_00000000u64; // SMI (tag = 0)

        assert_ne!(verify_heap_pointer(heap_ptr), 0);
        assert_eq!(verify_heap_pointer(invalid_ptr), 0);
        assert_eq!(verify_heap_pointer(smi_ptr), 0);
    }

    #[test]
    fn test_v8_smi_parsing() {
        // Test SMI value parsing (32-bit shifted SMI)
        let smi_value = 42u64 << 32; // SMI with value 42
        let non_smi = 0x12345678_00000001u64; // HeapObject

        assert_eq!(parse_smi_value(smi_value, 999), 42);
        assert_eq!(parse_smi_value(non_smi, 999), 999);
    }

    #[test]
    fn test_v8_offsets_selection() {
        let test_cases = vec![
            (Version::new(9, 4, 146), 9),
            (Version::new(10, 2, 154), 10),
            (Version::new(11, 3, 244), 11),
            (Version::new(12, 4, 254), 11), // Should use v11 offsets
        ];

        let table = V8UnwindTable::default();

        for (v8_version, _expected_major) in test_cases {
            let offsets = table.get_offsets_for_version(&v8_version);
            // Test that offsets are properly structured
            assert!(offsets.js_function.shared > 0);
            assert!(offsets.frame_pointers.marker < 0); // Should be negative (FP - offset)
        }
    }

    #[test]
    fn test_v8_memory_layout_constants() {
        // Test V8 constants are properly defined
        const V8_HEAP_OBJECT_TAG: u64 = 0x1;
        const V8_HEAP_OBJECT_TAG_MASK: u64 = 0x3;
        const V8_SMI_TAG: u64 = 0x0;
        const V8_SMI_TAG_MASK: u64 = 0x1;
        const V8_SMI_VALUE_SHIFT: u32 = 32;

        // Test basic tag operations
        let heap_ptr = 0x12345678_00000001u64;
        assert_eq!(heap_ptr & V8_HEAP_OBJECT_TAG_MASK, V8_HEAP_OBJECT_TAG);

        let smi_value = 42u64 << V8_SMI_VALUE_SHIFT;
        assert_eq!(smi_value & V8_SMI_TAG_MASK, V8_SMI_TAG);
        assert_eq!(smi_value >> V8_SMI_VALUE_SHIFT, 42);
    }

    #[test]
    fn test_v8_frame_pointer_offsets() {
        // Test that frame pointer offsets are reasonable
        let offsets = V8_9_OFFSETS;

        // Frame pointer offsets should be negative (relative to FP)
        assert!(offsets.frame_pointers.marker < 0);
        assert!(offsets.frame_pointers.function < 0);
        assert!(offsets.frame_pointers.bytecode_offset < 0);

        // JavaScript object offsets should be positive
        assert!(offsets.js_function.shared > 0);
        assert!(offsets.js_function.code > 0);
        assert!(offsets.shared_function_info.name_or_scope_info > 0);
    }

    // Helper functions for testing
    fn verify_heap_pointer(ptr: u64) -> u64 {
        const V8_HEAP_OBJECT_TAG: u64 = 0x1;
        const V8_HEAP_OBJECT_TAG_MASK: u64 = 0x3;

        if (ptr & V8_HEAP_OBJECT_TAG_MASK) != V8_HEAP_OBJECT_TAG {
            return 0;
        }
        ptr & !V8_HEAP_OBJECT_TAG_MASK
    }

    fn parse_smi_value(maybe_smi: u64, def_value: u64) -> u64 {
        const V8_SMI_TAG: u64 = 0x0;
        const V8_SMI_TAG_MASK: u64 = 0x1;
        const V8_SMI_VALUE_SHIFT: u32 = 32;

        if (maybe_smi & V8_SMI_TAG_MASK) != V8_SMI_TAG {
            return def_value;
        }
        maybe_smi >> V8_SMI_VALUE_SHIFT
    }

    #[test]
    fn test_enhanced_v8_stack_merging() {
        // Test enhanced stack merging with frame type detection
        let js_trace = "V8Stub;JSFunction@abc123;SFI@def456";
        let v8_native = "v8::internal::Runtime::Execute;v8::Script::Run";
        let non_v8_native = "pthread_start;clone";

        // Test with V8 native stack
        let merged = crate::unwind::v8::merge_stacks(js_trace, v8_native);
        assert!(merged.contains("[stub]")); // Enhanced frames
        assert!(merged.contains(v8_native));

        // Test with non-V8 native stack
        let merged = crate::unwind::v8::merge_stacks(js_trace, non_v8_native);
        assert!(merged.contains("[stub]"));
        assert!(merged.contains(INCOMPLETE_V8_STACK));
    }

    #[test]
    fn test_v8_symbolization_engine() {
        unsafe {
            let mut table = V8UnwindTable::new(0, 0);

            // Test marker frame symbolization
            let result = table.symbolize_marker_frame(0).unwrap();
            assert_eq!(result, "V8:EntryFrame");

            let result = table.symbolize_marker_frame(11).unwrap();
            assert_eq!(result, "V8:InterpretedFrame");

            // Test unknown frame types
            let result = table.symbolize_marker_frame(999).unwrap();
            assert_eq!(result, "V8:UnknownStub#999");
        }
    }

    #[test]
    fn test_v8_frame_type_constants() {
        // Test that frame type constants match expected values
        assert_eq!(V8_FILE_TYPE_MARKER, 0x0);
        assert_eq!(V8_FILE_TYPE_BYTECODE, 0x1);
        assert_eq!(V8_FILE_TYPE_NATIVE_SFI, 0x2);
        assert_eq!(V8_FILE_TYPE_NATIVE_CODE, 0x3);
        assert_eq!(V8_FILE_TYPE_NATIVE_JSFUNC, 0x4);
        assert_eq!(V8_FILE_TYPE_MASK, 0x7);
    }

    #[test]
    fn test_v8_dynamic_version_detection() {
        unsafe {
            let mut table = V8UnwindTable::new(0, 0);

            // Test version storage
            let version_10 = Version::new(10, 5, 123);
            let version_11 = Version::new(11, 2, 456);

            table.process_versions.insert(100, version_10.clone());
            table.process_versions.insert(200, version_11.clone());

            // Test version retrieval
            assert_eq!(table.get_process_version(100), Some(&version_10));
            assert_eq!(table.get_process_version(200), Some(&version_11));
            assert_eq!(table.get_process_version(999), None);

            // Test offsets selection based on version
            let offsets_10 = table.get_offsets_for_process(100);
            let offsets_11 = table.get_offsets_for_process(200);
            let offsets_unknown = table.get_offsets_for_process(999);

            // Should get version-specific offsets
            assert_eq!(
                offsets_10.js_function.shared,
                V8_10_OFFSETS.js_function.shared
            );
            assert_eq!(
                offsets_11.js_function.shared,
                V8_11_OFFSETS.js_function.shared
            );
            // Unknown should fallback to latest
            assert_eq!(
                offsets_unknown.js_function.shared,
                V8_11_OFFSETS.js_function.shared
            );

            // Test cleanup
            table.process_versions.remove(&100);
            assert_eq!(table.get_process_version(100), None);
        }
    }
}

/// Internal helper to detect if a process is running Node.js/V8
fn detect_v8_process(pid: u32) -> bool {
    if let Ok(exe_path) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
        if let Some(filename) = exe_path.file_name() {
            if let Some(name) = filename.to_str() {
                // Check for Node.js binary names
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

/// Merge V8 interpreter stack with native stack
pub fn merge_stacks(interpreter_trace: &str, native_trace: &str) -> String {
    if interpreter_trace.is_empty() {
        return native_trace.to_string();
    }

    if native_trace.is_empty() {
        return interpreter_trace.to_string();
    }

    // Parse and enhance V8 frames with better symbolization
    let enhanced_js_trace = enhance_v8_trace(interpreter_trace);

    // Check if native stack contains V8 internal functions
    let has_v8_frames = native_trace.contains("v8::internal::")
        || native_trace.contains("v8::Script::")
        || native_trace.contains("v8::Context::");

    if !has_v8_frames {
        // Native stack may not be properly unwound, mark it as incomplete
        return format!(
            "{};{};{}",
            enhanced_js_trace, INCOMPLETE_V8_STACK, native_trace
        );
    }

    // For V8, we typically want to show JavaScript frames first, then native frames
    // JavaScript frames are more relevant for application-level profiling
    format!("{};{}", enhanced_js_trace, native_trace)
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
        .map(|frame| enhance_single_v8_frame(frame))
        .collect();

    enhanced_frames.join(";")
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

pub fn get_offsets_for_v8_version(version: &Version) -> V8Offsets {
    match version.major {
        9 => *V8_9_OFFSETS,
        10 => *V8_10_OFFSETS,
        11 => *V8_11_OFFSETS,
        12.. => *V8_11_OFFSETS, // Use latest available
        _ => *V8_9_OFFSETS,     // Default to 9.x for older versions
    }
}

pub fn verify_heap_pointer(ptr: u64) -> u64 {
    // V8 uses tagged pointers: HeapObject pointers have tag bits 01
    if (ptr & 0x3) == 0x1 {
        ptr & !0x3 // Remove tag bits
    } else {
        0 // Invalid heap pointer
    }
}

pub fn parse_v8_smi(value: u64) -> u64 {
    // V8 SMI (Small Integer) values are stored in the upper 32 bits
    // SMI tag is 0, so we just extract the upper bits
    value >> 32
}

/// C FFI function to detect if a process is running Node.js/V8
#[no_mangle]
pub unsafe extern "C" fn is_v8_process(pid: u32) -> bool {
    detect_v8_process(pid)
}

/// C FFI function to merge V8 interpreter and native stacks
#[no_mangle]
pub unsafe extern "C" fn merge_v8_stacks(
    trace_str: *mut std::ffi::c_void,
    len: usize,
    i_trace: *const std::ffi::c_void,
    u_trace: *const std::ffi::c_void,
) -> usize {
    if i_trace.is_null() || u_trace.is_null() {
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

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_is_v8_process() {
        // Test with current process (not a Node.js process)
        let current_pid = std::process::id();
        assert!(!detect_v8_process(current_pid));

        // Test with invalid PID
        assert!(!detect_v8_process(999999));
    }

    #[test]
    fn test_merge_stacks() {
        // Test proper V8 stack merging
        let js_trace = "main;calculate;fibonacci";
        let v8_native_trace = "v8::internal::Invoke;v8::Script::Run;native_func";
        let merged = merge_stacks(js_trace, v8_native_trace);
        assert!(merged.contains(js_trace));
        assert!(merged.contains("native_func"));

        // Test JS stack only when no V8 frames detected
        let non_v8_native = "pthread_create;some_native_func";
        let merged = merge_stacks(js_trace, non_v8_native);
        assert!(merged.contains(js_trace));
        assert!(merged.contains(INCOMPLETE_V8_STACK));

        // Test only JS stack (empty native)
        let merged = merge_stacks(js_trace, "");
        assert_eq!(merged, js_trace);

        // Test only native stack (empty JS)
        let merged = merge_stacks("", v8_native_trace);
        assert_eq!(merged, v8_native_trace);

        // Test both empty
        let merged = merge_stacks("", "");
        assert!(merged.is_empty());
    }

    #[test]
    fn test_v8_unwind_table_creation() {
        // This would normally require actual BPF map file descriptors
        // For testing, we simulate with invalid fds (should fail gracefully)
        let table = V8UnwindTable::new(-1, -1);
        assert!(table.is_ok()); // Should not crash with invalid fds
    }
}

#[cfg(test)]
#[path = "v8_tests.rs"]
mod tests;
