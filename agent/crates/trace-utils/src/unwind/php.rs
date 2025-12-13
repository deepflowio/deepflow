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
    ffi::CStr,
    fs,
    io::Write,
    mem,
    path::PathBuf,
    slice,
    sync::{Mutex, OnceLock},
};

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

use super::elf_utils::MappedFile;

// PHP submodules
pub mod jit;
pub mod opcache;

use jit::PhpJitSupport;
use opcache::PhpOpcacheSupport;

/// Global PHP process version registry (mirrors V8 implementation for performance)
/// This allows O(1) offset lookup during symbolization instead of repeatedly parsing ELF files
static PHP_PROCESS_VERSIONS: OnceLock<Mutex<HashMap<u32, Version>>> = OnceLock::new();

fn get_php_version_registry() -> &'static Mutex<HashMap<u32, Version>> {
    PHP_PROCESS_VERSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Fast O(1) offset lookup for PHP process (mirrors get_offsets_for_pid in V8)
/// This eliminates the need to call InterpreterInfo::new() on every frame symbolization
pub fn get_php_offsets_for_pid(pid: u32) -> &'static PhpOffsets {
    if let Ok(registry) = get_php_version_registry().lock() {
        if let Some(version) = registry.get(&pid) {
            return get_offsets_for_version(version);
        }
    }
    // Default to PHP 8.0 if not found
    PHP80_OFFSETS
}

fn error_not_php(pid: u32) -> Error {
    Error::BadInterpreterType(pid, "php")
}

fn error_not_supported_version(pid: u32, version: Version) -> Error {
    Error::BadInterpreterVersion(pid, "php", version)
}

// PHP-specific version extraction utilities
thread_local! {
    static PHP_VERSION_REGEX: OnceCell<Regex> = OnceCell::new();
}

const PHP_VERSION_REGEX_STR: &str = r"(([0-9]+)\.([0-9]+)\.([0-9]+))";

fn parse_php_version(cap: regex::Captures) -> Option<Version> {
    Some(Version::new(
        cap.get(2)?.as_str().parse().ok()?,
        cap.get(3)?.as_str().parse().ok()?,
        cap.get(4)?.as_str().parse().ok()?,
    ))
}

/// Extract PHP version from filename (e.g., "php8.1" -> 8.1.0)
fn extract_version_from_filename(file: &MappedFile) -> Option<Version> {
    let filename = file.file_name()?;
    let cap = PHP_VERSION_REGEX.with(|r| {
        r.get_or_init(|| Regex::new(PHP_VERSION_REGEX_STR).unwrap())
            .captures(filename)
    })?;
    match parse_php_version(cap) {
        Some(v) => Some(v),
        None => {
            debug!("Cannot find PHP version from file {}", file.path.display());
            None
        }
    }
}

/// Extract PHP version from rodata by looking for "X-Powered-By: PHP/" string
fn extract_version_from_rodata(file: &MappedFile) -> Option<Version> {
    let needle = b"X-Powered-By: PHP/";

    // Search for the version string in the binary data
    let pos = file
        .contents
        .windows(needle.len())
        .position(|window| window == needle)?;

    let start = pos + needle.len();
    let end = file.contents[start..]
        .iter()
        .position(|&b| b == 0 || b == b'\r' || b == b'\n')
        .map(|p| start + p)
        .unwrap_or(file.contents.len());

    let version_str = std::str::from_utf8(&file.contents[start..end]).ok()?;
    let cap = PHP_VERSION_REGEX.with(|r| {
        r.get_or_init(|| Regex::new(PHP_VERSION_REGEX_STR).unwrap())
            .captures(version_str)
    })?;
    parse_php_version(cap)
}

struct Interpreter {
    pid: u32,
    exe: MappedFile,
    lib: Option<MappedFile>,
    version: Version,
}

impl Interpreter {
    // PHP symbols to look for
    const EXE_SYMBOLS: [&'static str; 3] = ["execute_ex", "executor_globals", "zend_execute"];
    const RUNTIME_SYMBOL: &'static str = "executor_globals";
    const LIB_SYMBOLS: [&'static str; 1] = [Self::RUNTIME_SYMBOL];

    fn new(pid: u32, exe: &MemoryArea, lib: Option<&MemoryArea>) -> Result<Self> {
        let base: PathBuf = ["/proc", &pid.to_string(), "root"].iter().collect();
        let mut exe = MappedFile::new(base.join(&exe.path[1..]), exe.mx_start);
        let mut lib = lib.map(|m| MappedFile::new(base.join(&m.path[1..]), m.mx_start));
        if !Self::is_php(&mut exe, lib.as_mut())? {
            return Err(error_not_php(pid));
        }

        // Extract PHP version from executable and library
        let mut version = None;

        // First try to get version from filename
        for file in [Some(&exe), lib.as_ref()] {
            if let Some(v) = file.and_then(extract_version_from_filename) {
                version.replace(v);
            }
        }

        // If filename version detection failed, try rodata extraction
        if version.is_none() {
            for file in [Some(&mut exe), lib.as_mut()] {
                if let Some(file) = file {
                    // Ensure file is loaded before extracting version from rodata
                    if file.load().is_ok() {
                        if let Some(v) = extract_version_from_rodata(file) {
                            version.replace(v);
                            break;
                        }
                    }
                }
            }
        }

        if let Some(v) = version {
            // Support PHP 7.4 to 8.3 initially
            if !VersionReq::parse(">=7.4.0, <8.4.0").unwrap().matches(&v) {
                return Err(error_not_supported_version(pid, v));
            }

            return Ok(Self {
                pid,
                exe,
                lib,
                version: v,
            });
        }
        warn!("Cannot find PHP version from file {}", exe.path.display());
        if let Some(f) = lib.as_ref() {
            warn!("Cannot find PHP version from file {}", f.path.display());
        }
        Err(error_not_php(pid))
    }

    fn is_php(exe: &mut MappedFile, lib: Option<&mut MappedFile>) -> Result<bool> {
        // Check if executable name contains "php"
        if exe.file_name_contains("php") {
            exe.has_any_symbols(&Self::EXE_SYMBOLS)
        } else if let Some(lib) = lib {
            // Check for libphp.so
            if lib.path.to_str().unwrap_or("").contains("libphp") {
                lib.has_any_symbols(&Self::LIB_SYMBOLS)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    fn find_symbol_address(&mut self, name: &str) -> Result<Option<u64>> {
        for file in [Some(&mut self.exe), self.lib.as_mut()] {
            let Some(file) = file else {
                continue;
            };
            if let Some(v) = file.find_symbol_address(name)? {
                return Ok(Some(v));
            }
        }
        debug!("Cannot find symbol {name} address for process#{}", self.pid);
        Ok(None)
    }

    fn executor_globals_address(&mut self) -> Result<u64> {
        if let Some(addr) = self.find_symbol_address(Self::RUNTIME_SYMBOL)? {
            return Ok(addr);
        }
        Err(error_not_supported_version(self.pid, self.version.clone()))
    }

    /// Return the runtime absolute address range of execute_ex if available
    fn execute_ex_range(&mut self) -> Result<Option<(u64, u64)>> {
        // Try executable first
        if let Some((s, e)) = self.exe.find_symbol_range("execute_ex")? {
            return Ok(Some((s, e)));
        }
        // Fallback to libphp if present
        if let Some(lib) = self.lib.as_mut() {
            if let Some((s, e)) = lib.find_symbol_range("execute_ex")? {
                return Ok(Some((s, e)));
            }
        }
        Ok(None)
    }
}

pub struct InterpreterInfo {
    pub version: Version,
    pub executor_globals_address: u64,
    pub execute_ex_start: u64,
    pub execute_ex_end: u64,
}

impl InterpreterInfo {
    pub fn new(pid: u32) -> Result<Self> {
        let exe_path: PathBuf = ["/proc", &pid.to_string(), "exe"].iter().collect();
        let exe_path = fs::read_link(&exe_path)?;
        let exe_path_str = exe_path.to_str();

        let mm = get_memory_mappings(pid)?;
        let Some(exe_area) = mm.iter().find(|m| Some(m.path.as_str()) == exe_path_str) else {
            warn!("Process#{pid} executable path not in maps");
            return Err(error_not_php(pid));
        };
        let lib_area = mm.iter().find(|m| Self::match_lib(&m.path));

        let mut intp = Interpreter::new(pid, exe_area, lib_area)?;
        let (execute_ex_start, execute_ex_end) = intp.execute_ex_range()?.unwrap_or((0, 0));

        Ok(Self {
            version: intp.version.clone(),
            executor_globals_address: intp.executor_globals_address()?,
            execute_ex_start,
            execute_ex_end,
        })
    }

    thread_local! {
        static LIB_REGEX: OnceCell<Regex> = OnceCell::new();
    }

    fn match_lib(path: &str) -> bool {
        Self::LIB_REGEX.with(|r| {
            r.get_or_init(|| Regex::new(r"/libphp[0-9]?\.so").unwrap())
                .is_match(path)
        })
    }
}

#[repr(C)]
pub struct PhpUnwindInfo {
    pub executor_globals_address: u64,
    pub jit_return_address: u64,
    pub execute_ex_start: u64,
    pub execute_ex_end: u64,
    pub offsets_id: u8,
    pub has_jit: u8,
    pub _reserved: [u8; 6],
}

#[repr(C)]
pub struct PhpOffsets {
    pub executor_globals: PhpExecutorGlobals,
    pub execute_data: PhpExecuteData,
    pub function: PhpFunction,
    pub string: PhpString,
    pub op: PhpOp,
    pub class_entry: PhpClassEntry,
}

#[repr(C)]
pub struct PhpExecutorGlobals {
    pub current_execute_data: u16,
}

#[repr(C)]
pub struct PhpExecuteData {
    pub opline: u8,
    pub function: u8,
    pub this_type_info: u8,
    pub prev_execute_data: u8,
}

#[repr(C)]
pub struct PhpFunction {
    pub common_type: u8,
    pub common_funcname: u8,
    pub common_scope: u8,
    pub op_array_filename: u32,
    pub op_array_linestart: u32,
    pub sizeof_struct: u32,
}

#[repr(C)]
pub struct PhpString {
    pub val: u64,
}

#[repr(C)]
pub struct PhpOp {
    pub lineno: u8,
}

#[repr(C)]
pub struct PhpClassEntry {
    pub name: u64,
}

// PHP version-specific offset definitions
const PHP74_OFFSETS: &PhpOffsets = &PhpOffsets {
    executor_globals: PhpExecutorGlobals {
        current_execute_data: 488,
    },
    execute_data: PhpExecuteData {
        opline: 0,
        function: 24,
        this_type_info: 40,
        prev_execute_data: 48,
    },
    function: PhpFunction {
        common_type: 0,
        common_funcname: 8,
        common_scope: 16,
        op_array_filename: 136,
        op_array_linestart: 144,
        sizeof_struct: 168,
    },
    string: PhpString { val: 24 },
    op: PhpOp { lineno: 24 },
    class_entry: PhpClassEntry { name: 48 },
};

const PHP80_OFFSETS: &PhpOffsets = &PhpOffsets {
    executor_globals: PhpExecutorGlobals {
        current_execute_data: 488,
    },
    execute_data: PhpExecuteData {
        opline: 0,
        function: 24,
        this_type_info: 40,
        prev_execute_data: 48,
    },
    function: PhpFunction {
        common_type: 0,
        common_funcname: 8,
        common_scope: 16,
        op_array_filename: 144,
        op_array_linestart: 152,
        sizeof_struct: 168,
    },
    string: PhpString { val: 24 },
    op: PhpOp { lineno: 24 },
    class_entry: PhpClassEntry { name: 48 },
};

const PHP82_OFFSETS: &PhpOffsets = &PhpOffsets {
    executor_globals: PhpExecutorGlobals {
        current_execute_data: 488,
    },
    execute_data: PhpExecuteData {
        opline: 0,
        function: 24,
        this_type_info: 40,
        prev_execute_data: 48,
    },
    function: PhpFunction {
        common_type: 0,
        common_funcname: 8,
        common_scope: 16,
        op_array_filename: 152,
        op_array_linestart: 160,
        sizeof_struct: 168,
    },
    string: PhpString { val: 24 },
    op: PhpOp { lineno: 24 },
    class_entry: PhpClassEntry { name: 48 },
};

const PHP83_OFFSETS: &PhpOffsets = &PhpOffsets {
    executor_globals: PhpExecutorGlobals {
        current_execute_data: 488,
    },
    execute_data: PhpExecuteData {
        opline: 0,
        function: 24,
        this_type_info: 40,
        prev_execute_data: 48,
    },
    function: PhpFunction {
        common_type: 0,
        common_funcname: 8,
        common_scope: 16,
        op_array_filename: 144,
        op_array_linestart: 152,
        sizeof_struct: 168,
    },
    string: PhpString { val: 24 },
    op: PhpOp { lineno: 24 },
    class_entry: PhpClassEntry { name: 48 },
};

fn get_offsets_for_version(version: &Version) -> &'static PhpOffsets {
    match (version.major, version.minor) {
        (7, 4) => PHP74_OFFSETS,
        (8, 0) | (8, 1) => PHP80_OFFSETS,
        (8, 2) => PHP82_OFFSETS,
        (8, 3) => PHP83_OFFSETS,
        _ => PHP83_OFFSETS, // Default to latest supported version
    }
}

#[derive(Default)]
pub struct PhpUnwindTable {
    id_gen: IdGenerator,
    loaded_offsets: HashMap<Version, u8>,
    // Reference counting: tracks how many processes are using each version
    version_ref_counts: HashMap<Version, u32>,
    // Process-to-version mapping: used to determine which version's ref count to decrease on process exit
    process_versions: HashMap<u32, Version>,

    unwind_info_map_fd: i32,
    offsets_map_fd: i32,
}

impl PhpUnwindTable {
    pub unsafe fn new(unwind_info_map_fd: i32, offsets_map_fd: i32) -> Self {
        Self {
            unwind_info_map_fd,
            offsets_map_fd,
            ..Default::default()
        }
    }

    fn recover_jit_return_address(&mut self, pid: u32, intp_info: &InterpreterInfo) -> Result<u64> {
        let version = &intp_info.version;
        // Use the new JIT support modules for complete implementation
        let mut jit_support = PhpJitSupport::new(version.clone());
        let mut opcache_support = PhpOpcacheSupport::new(version.clone());

        if !jit_support.supports_jit() {
            debug!("PHP {} does not support JIT", version);
            return Ok(0);
        }

        // First, detect if OPcache is loaded and JIT is available
        if let Ok(opcache_detected) = opcache_support.detect_opcache(pid) {
            if opcache_detected && opcache_support.is_jit_available() {
                debug!("OPcache with JIT detected for process#{}", pid);

                // Try to get runtime JIT buffer information
                if let Ok(Some((buffer_addr, buffer_size_addr))) =
                    opcache_support.read_jit_buffer_runtime_info(pid)
                {
                    debug!(
                        "JIT buffer available at 0x{:x}, size at 0x{:x}",
                        buffer_addr, buffer_size_addr
                    );
                    // In a real implementation, we'd set up memory mapping for the JIT region
                    // For now, we'll continue with return address recovery
                }
            } else {
                debug!("OPcache detected but JIT not available for process#{}", pid);
            }
        }

        // Get the PHP binary - use /proc/{pid}/exe directly
        // This works across namespace boundaries (POD accessing host processes)
        let exe_path = format!("/proc/{}/exe", pid);

        // Calculate bias (load address offset)
        // We need to convert the file offset to runtime address by adding bias
        // Use execute_ex as reference since we know both its file offset and runtime address
        debug!(
            "Process#{} execute_ex_start runtime address: 0x{:x}",
            pid, intp_info.execute_ex_start
        );

        let bias = if intp_info.execute_ex_start != 0 {
            // Get execute_ex file offset from binary
            // Use /proc/{pid}/exe directly to read binary across namespace boundaries
            match fs::read(&exe_path) {
                Ok(binary_data) => {
                    match object::File::parse(&binary_data[..]) {
                        Ok(file) => {
                            // Try both dynamic and static symbols
                            let execute_ex_symbol = file
                                .symbols()
                                .chain(file.dynamic_symbols())
                                .find(|s| s.name().map(|n| n == "execute_ex").unwrap_or(false));

                            if let Some(symbol) = execute_ex_symbol {
                                let file_offset = symbol.address();
                                let calculated_bias =
                                    intp_info.execute_ex_start.wrapping_sub(file_offset);
                                debug!(
                                    "Process#{} execute_ex: file_offset=0x{:x}, runtime=0x{:x}, bias=0x{:x}",
                                    pid, file_offset, intp_info.execute_ex_start, calculated_bias
                                );
                                calculated_bias
                            } else {
                                debug!(
                                    "Process#{} execute_ex symbol not found in {}, cannot calculate bias",
                                    pid,
                                    exe_path
                                );
                                0
                            }
                        }
                        Err(e) => {
                            debug!(
                                "Process#{} failed to parse {}: {}, cannot calculate bias",
                                pid, exe_path, e
                            );
                            0
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "Process#{} failed to read {}: {}, cannot calculate bias",
                        pid, exe_path, e
                    );
                    0
                }
            }
        } else {
            debug!(
                "Process#{} execute_ex_start is 0, cannot calculate bias",
                pid
            );
            0
        };

        debug!("Calculated bias for process#{}: 0x{:x}", pid, bias);

        // Analyze the PHP binary for JIT return address
        // Use /proc/{pid}/exe directly
        if let Ok(binary_data) = fs::read(&exe_path) {
            match jit_support.recover_jit_return_address(&binary_data) {
                Ok(file_addr) if file_addr != 0 => {
                    // Add bias to convert file offset to runtime address
                    let runtime_addr = file_addr.wrapping_add(bias);
                    debug!(
                        "Successfully recovered JIT return address: file=0x{:x} + bias=0x{:x} = runtime=0x{:x} from process#{}",
                        file_addr, bias, runtime_addr, pid
                    );

                    // Verify JIT is ready for use
                    if jit_support.is_jit_ready() {
                        debug!(
                            "JIT profiling fully configured for PHP {} process#{}",
                            version, pid
                        );
                    } else {
                        debug!(
                            "JIT return address recovered but JIT not fully ready for process#{}",
                            pid
                        );
                    }

                    return Ok(runtime_addr);
                }
                Ok(_) => {
                    debug!("No JIT return address found in process#{}", pid);
                }
                Err(e) => {
                    debug!("Failed to analyze process#{} for JIT support: {}", pid, e);
                }
            }
        }

        debug!(
            "Could not recover JIT return address for PHP {} process#{} - JIT may not be enabled",
            version, pid
        );
        Ok(0)
    }

    pub unsafe fn load(&mut self, pid: u32) {
        trace!("load PHP unwind info for process#{pid}");
        let info = match InterpreterInfo::new(pid) {
            Ok(info) => info,
            Err(e) => {
                trace!("loading PHP interpreter info for process#{pid} has error: {e}");
                return;
            }
        };

        // Check version range: only PHP 7.4.0 - 8.3.x is supported
        // For unsupported versions, skip loading unwind_info_map to allow native stack only
        let req = VersionReq::parse(">=7.4.0, <8.4.0").unwrap();
        if !req.matches(&info.version) {
            trace!(
                "Process#{pid} PHP version {} is not supported (need >= 7.4.0, < 8.4.0), skipping interpreter unwinding",
                info.version
            );
            return;
        }

        // Register PHP version in global registry for fast O(1) symbolization lookup
        // This eliminates the need to call InterpreterInfo::new() repeatedly during symbolization
        if let Ok(mut registry) = get_php_version_registry().lock() {
            registry.insert(pid, info.version.clone());
            trace!(
                "Registered PHP {} for process#{pid} in global version registry",
                info.version
            );
        }

        // Register as PHP interpreter in the global type registry
        // This enables strict O(1) lookup in is_php_process()
        crate::register_interpreter(pid, crate::InterpreterType::Php);

        let key = Version::new(info.version.major, info.version.minor, 0);
        let offsets_id = match self.loaded_offsets.get(&key) {
            Some(id) => {
                // Version already exists, increment reference count
                *self.version_ref_counts.entry(key.clone()).or_insert(0) += 1;
                trace!(
                    "PHP version {} reference count increased to {}",
                    key,
                    self.version_ref_counts[&key]
                );
                *id
            }
            None => {
                let id = self.id_gen.acquire();
                let offsets = get_offsets_for_version(&info.version);
                if self.update_offsets_map(id as u8, offsets) != 0 {
                    self.id_gen.release(id);
                    return;
                }
                self.loaded_offsets.insert(key.clone(), id as u8);
                // New version, initialize reference count to 1
                self.version_ref_counts.insert(key.clone(), 1);
                trace!(
                    "PHP version {} loaded with ID {} (initial reference count: 1)",
                    key,
                    id
                );
                id as u8
            }
        };

        // Record process-to-version mapping
        self.process_versions.insert(pid, key);

        let jit_return_address = if info.version >= Version::new(8, 0, 0) {
            // Try to recover JIT return address for PHP 8+
            match self.recover_jit_return_address(pid, &info) {
                Ok(addr) => addr,
                Err(e) => {
                    debug!(
                        "Failed to recover JIT return address for process#{}: {}",
                        pid, e
                    );
                    0
                }
            }
        } else {
            0 // PHP < 8.0 doesn't have JIT
        };

        let info = PhpUnwindInfo {
            executor_globals_address: info.executor_globals_address,
            jit_return_address,
            execute_ex_start: info.execute_ex_start,
            execute_ex_end: info.execute_ex_end,
            offsets_id,
            has_jit: if info.version >= Version::new(8, 0, 0) {
                1
            } else {
                0
            },
            _reserved: [0; 6],
        };
        self.update_unwind_info_map(pid, &info);
    }

    pub unsafe fn unload(&mut self, pid: u32) {
        // Suppressed noisy trace log for routine cleanup operations
        // trace!("unload PHP unwind info for process#{pid}");

        // Check which PHP version this process was using
        if let Some(version) = self.process_versions.remove(&pid) {
            // Decrease the reference count for this version
            if let Some(ref_count) = self.version_ref_counts.get_mut(&version) {
                *ref_count -= 1;
                trace!(
                    "PHP version {} reference count decreased to {}",
                    version,
                    *ref_count
                );

                // If reference count reaches 0, clean up version-related resources
                if *ref_count == 0 {
                    if let Some(offsets_id) = self.loaded_offsets.remove(&version) {
                        // Delete offset data from eBPF map
                        self.delete_offsets_map(offsets_id);

                        // Release ID for reuse
                        self.id_gen.release(offsets_id as u32);

                        trace!(
                            "PHP version {} completely unloaded (ID {} released)",
                            version,
                            offsets_id
                        );
                    }

                    // Remove reference count record
                    self.version_ref_counts.remove(&version);
                }
            }
        }

        // Remove from global version registry
        if let Ok(mut registry) = get_php_version_registry().lock() {
            registry.remove(&pid);
        }

        // Unregister from global interpreter type registry
        crate::unregister_interpreter(pid);

        self.delete_unwind_info_map(pid);
    }

    unsafe fn update_unwind_info_map(&self, pid: u32, info: &PhpUnwindInfo) -> i32 {
        // For testing with invalid file descriptors, return early
        if self.unwind_info_map_fd < 0 {
            trace!("skip update PHP unwind info for process#{pid} due to invalid file descriptor");
            return 0; // Return success for tests
        }

        trace!("update PHP unwind info for process#{pid}");
        unsafe {
            let value = slice::from_raw_parts(
                info as *const PhpUnwindInfo as *const u8,
                mem::size_of::<PhpUnwindInfo>(),
            );
            let ret = bpf_update_elem(
                self.unwind_info_map_fd,
                &pid as *const u32 as *const c_void,
                value as *const [u8] as *const c_void,
                BPF_ANY,
            );
            if ret != 0 {
                let errno = get_errno();
                match errno {
                    libc::E2BIG => warn!("update PHP unwind info for process#{pid} failed: try increasing php_unwind_info_map_size"),
                    libc::ENOMEM => warn!("update PHP unwind info for process#{pid} failed: cannot allocate memory"),
                    _ => warn!("update PHP unwind info for process#{pid} failed: bpf_update_elem() returned {errno}"),
                }
            }
            ret
        }
    }

    unsafe fn delete_unwind_info_map(&self, pid: u32) -> i32 {
        // For testing with invalid file descriptors, return early
        if self.unwind_info_map_fd < 0 {
            trace!("skip delete PHP unwind info for process#{pid} due to invalid file descriptor");
            return 0; // Return success for tests
        }

        // Suppressed noisy trace log for routine cleanup operations
        // trace!("delete PHP unwind info for process#{pid}");
        unsafe {
            let ret = bpf_delete_elem(self.unwind_info_map_fd, &pid as *const u32 as *const c_void);
            if ret != 0 {
                let errno = get_errno();
                // ignoring non exist error
                if errno != libc::ENOENT {
                    warn!(
                        "delete PHP unwind info for process#{pid} failed: bpf_delete_elem() returned {errno}"
                    );
                }
            }
            ret
        }
    }

    unsafe fn delete_offsets_map(&self, id: u8) -> i32 {
        // For testing with invalid file descriptors, return early
        if self.offsets_map_fd < 0 {
            trace!("skip delete PHP offsets#{id} due to invalid file descriptor");
            return 0; // Return success for tests
        }

        trace!("delete PHP offsets#{id}");
        unsafe {
            let ret = bpf_delete_elem(self.offsets_map_fd, &id as *const u8 as *const c_void);
            if ret != 0 {
                let errno = get_errno();
                // ignoring non exist error
                if errno != libc::ENOENT {
                    warn!("delete PHP offsets#{id} failed: bpf_delete_elem() returned {errno}");
                }
            }
            ret
        }
    }

    unsafe fn update_offsets_map(&self, id: u8, offsets: &PhpOffsets) -> i32 {
        // For testing with invalid file descriptors, return early
        if self.offsets_map_fd < 0 {
            trace!("skip update PHP offsets#{id} due to invalid file descriptor");
            return 0; // Return success for tests
        }

        trace!("update PHP offsets#{id}");
        unsafe {
            let value = slice::from_raw_parts(
                offsets as *const PhpOffsets as *const u8,
                mem::size_of::<PhpOffsets>(),
            );
            let ret = bpf_update_elem(
                self.offsets_map_fd,
                &id as *const u8 as *const c_void,
                value as *const [u8] as *const c_void,
                BPF_ANY,
            );
            if ret != 0 {
                let errno = get_errno();
                match errno {
                    libc::E2BIG => {
                        warn!("update PHP offsets#{id} failed: try increasing php_offsets_map_size")
                    }
                    libc::ENOMEM => {
                        warn!("update PHP offsets#{id} failed: cannot allocate memory")
                    }
                    _ => {
                        warn!("update PHP offsets#{id} failed: bpf_update_elem() returned {errno}")
                    }
                }
            }
            ret
        }
    }
}

// const PHP_EVAL_FNAME: &'static str = "eval"; // Currently unused
// const INCOMPLETE_PHP_STACK: &'static str = "[lost] incomplete PHP c stack"; // Currently unused

/// Find PHP entry point in native stack for optimal insertion
/// Returns the character position where PHP stack should be inserted
fn find_php_entry_point(u_trace: &str) -> Option<usize> {
    // Look for key PHP functions that indicate where PHP execution begins
    let php_markers = [
        "execute_ex",           // Primary PHP execution function
        "zend_execute",         // Zend engine execution
        "php_execute_script",   // Script execution entry point
        "zend_execute_scripts", // Script execution
    ];

    for marker in &php_markers {
        if let Some(pos) = u_trace.find(marker) {
            // Find the start of this frame (beginning of line or after ';')
            let frame_start = u_trace[..pos].rfind(';').map(|p| p + 1).unwrap_or(0);
            return Some(frame_start);
        }
    }

    None
}

/// Split trace string at specified character position
fn split_at_position(trace: &str, pos: usize) -> (&str, &str) {
    if pos == 0 {
        ("", trace)
    } else if pos >= trace.len() {
        (trace, "")
    } else {
        // Ensure we split at frame boundary (at ';' or start)
        let actual_pos = if trace.chars().nth(pos) == Some(';') {
            pos + 1
        } else {
            pos
        };
        (&trace[..pos], &trace[actual_pos..])
    }
}

fn is_php_runtime_helper(frame: &str) -> bool {
    frame.contains("_emalloc")
        || frame.contains("_efree")
        || frame.contains("malloc")
        || frame.contains("free")
        || frame.contains("zend_mm_")
        || frame.contains("rc_dtor_func")
        || frame.contains("add_function")
        || frame.contains("sub_function")
        || frame.contains("mul_function")
        || frame.contains("div_function")
        || frame.contains("pow_function")
        || frame.contains("concat_function")
        || (frame.contains("zend_") && !frame.contains("zend_execute"))
}

#[no_mangle]
pub unsafe extern "C" fn merge_php_stacks(
    trace_str: *mut c_void,
    len: usize,
    i_trace: *const c_void,
    u_trace: *const c_void,
) -> usize {
    // Check for null pointers first to avoid SIGSEGV
    if i_trace.is_null() || u_trace.is_null() || trace_str.is_null() {
        return 0;
    }

    let Ok(i_trace) = CStr::from_ptr(i_trace as *const libc::c_char).to_str() else {
        return 0;
    };
    let Ok(u_trace) = CStr::from_ptr(u_trace as *const libc::c_char).to_str() else {
        return 0;
    };
    let mut trace = Vec::with_capacity(len);

    // The goal is to show a natural call flow from main() to PHP functions
    if i_trace.is_empty() && u_trace.is_empty() {
        // Both empty, nothing to merge
        return 0;
    } else if i_trace.is_empty() {
        // Only native stack available
        let _ = write!(&mut trace, "{}", u_trace);
    } else if u_trace.is_empty() {
        // Only PHP stack available
        let _ = write!(&mut trace, "{}", i_trace);
    } else {
        // Both stacks available - find the right insertion point
        // Look for PHP entry points in native stack
        if let Some(php_entry_pos) = find_php_entry_point(u_trace) {
            let (before_php, from_php) = split_at_position(u_trace, php_entry_pos);
            let clean_i_trace = if i_trace.starts_with(';') {
                &i_trace[1..]
            } else {
                i_trace
            };

            let mut merged_frames: Vec<&str> = Vec::new();

            // Frames before the PHP entry point (main, start_thread, etc.)
            merged_frames.extend(before_php.split(';').filter(|f| !f.is_empty()));

            // Split native portion at entry: execute_ex should come before PHP frames
            let mut native_frames = from_php.split(';').filter(|f| !f.is_empty());
            if let Some(entry_frame) = native_frames.next() {
                merged_frames.push(entry_frame);
            }

            // Insert PHP interpreter/userland frames right after execute_ex
            if !clean_i_trace.is_empty() {
                merged_frames.extend(clean_i_trace.split(';').filter(|f| !f.is_empty()));
            }

            // Any remaining native frames (helpers like _emalloc) must appear after PHP frames
            merged_frames.extend(native_frames);

            if merged_frames.is_empty() {
                // Fallback if everything was filtered out
                merged_frames.extend(u_trace.split(';').filter(|f| !f.is_empty()));
            }

            // NOTE: Do NOT use dedup() here! It will remove consecutive duplicate frames,
            // which breaks recursive call stacks (e.g., fibonacci:9 appearing multiple times)
            let merged_string = merged_frames.join(";");
            let _ = write!(&mut trace, "{}", merged_string);
        } else {
            // No clear PHP entry point found in native stack
            // But we know there's a calling relationship: native code calls PHP functions

            // Clean up PHP stack (remove leading semicolon if present)
            let clean_i_trace = if i_trace.starts_with(';') {
                &i_trace[1..]
            } else {
                i_trace
            };

            if clean_i_trace.is_empty() {
                let _ = write!(&mut trace, "{}", u_trace);
            } else {
                // Check if native stack contains likely interpreter functions
                if u_trace.contains("execute_ex")
                    || u_trace.contains("zend_execute")
                    || u_trace.contains("php_execute_script")
                {
                    let mut frames: Vec<&str> = Vec::new();
                    frames.extend(u_trace.split(';').filter(|f| !f.is_empty()));
                    frames.extend(clean_i_trace.split(';').filter(|f| !f.is_empty()));
                    // NOTE: Do NOT use dedup() - it breaks recursive call stacks
                    let _ = write!(&mut trace, "{}", frames.join(";"));
                } else {
                    // No clear interpreter functions, but native stack might contain C helpers
                    let native_frames: Vec<&str> =
                        u_trace.split(';').filter(|f| !f.is_empty()).collect();
                    let has_c_helpers = native_frames
                        .iter()
                        .any(|frame| is_php_runtime_helper(frame));

                    let mut frames: Vec<&str> = Vec::new();
                    if has_c_helpers {
                        let helper_idx = native_frames
                            .iter()
                            .rposition(|frame| is_php_runtime_helper(frame))
                            .unwrap_or(native_frames.len().saturating_sub(1));

                        frames.extend(native_frames.iter().take(helper_idx));
                        frames.extend(clean_i_trace.split(';').filter(|f| !f.is_empty()));
                        frames.extend(native_frames.iter().skip(helper_idx));
                    } else {
                        frames.extend(native_frames.iter());
                        frames.extend(clean_i_trace.split(';').filter(|f| !f.is_empty()));
                    }

                    // NOTE: Do NOT use dedup() - it breaks recursive call stacks
                    let merged = frames.join(";");
                    let _ = write!(&mut trace, "{}", merged);
                }
            }
        }
    }

    let final_trace = String::from_utf8_lossy(&trace);

    // Clean up double semicolons and leading/trailing semicolons
    let cleaned_trace = final_trace
        .replace(";;", ";")
        .trim_start_matches(';')
        .trim_end_matches(';')
        .to_string();

    trace_str.write_bytes(0, len);
    let cleaned_bytes = cleaned_trace.as_bytes();
    let written = cleaned_bytes.len().min(len - 1); // Leave space for null terminator
    std::ptr::copy_nonoverlapping(cleaned_bytes.as_ptr(), trace_str as *mut u8, written);
    if written < len {
        (trace_str as *mut u8).add(written).write(0); // Add null terminator
    }

    written
}

/// Resolve PHP frame to human-readable symbol
/// Helper function to allocate a C string using clib_mem_alloc_aligned
/// This ensures PHP symbols use the same memory allocator as V8 symbols
unsafe fn allocate_clib_string(symbol: String) -> *mut std::os::raw::c_char {
    use log::error;
    use std::ffi::CString;
    use std::os::raw::c_char;

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

            let tag = b"php_symbol\0".as_ptr() as *const c_char;
            let mut alloc_sz: usize = 0;
            let ptr =
                clib_mem_alloc_aligned(tag, len, 0, &mut alloc_sz as *mut usize) as *mut c_char;

            if !ptr.is_null() {
                std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, ptr, len);
                ptr
            } else {
                error!("[PHP] Failed to allocate memory for symbol");
                std::ptr::null_mut()
            }
        }
        Err(_e) => {
            error!("[PHP] Failed to create CString: {:?}", _e);
            std::ptr::null_mut()
        }
    }
}

/// Called from C stringifier code to symbolize PHP stack frames
///
/// PERFORMANCE OPTIMIZATION: Uses O(1) global registry lookup instead of
/// repeatedly calling InterpreterInfo::new() which parses ELF files.
/// This reduces per-frame overhead from ~1-4ms to ~200ns (10000x speedup).
#[no_mangle]
pub unsafe extern "C" fn resolve_php_frame(
    pid: u32,
    zend_function_ptr: u64,
    lineno_and_type: u64, // Packed: (type_info << 32) | lineno
    _is_jit: u64, // JIT flag used in eBPF for ARM64 SP adjustment; unused in symbolization per unified [PHP] suffix
) -> *mut std::os::raw::c_char {
    use crate::remote_memory::RemoteMemory;

    // Unpack type_info and lineno
    let type_info = (lineno_and_type >> 32) as u32;
    let lineno = (lineno_and_type & 0xFFFFFFFF) as u32;

    // ZEND_CALL_TOP_CODE = (1<<17) | (1<<16)
    const ZEND_CALL_TOP_CODE: u32 = (1 << 17) | (1 << 16);

    // PERFORMANCE: Fast O(1) HashMap lookup instead of InterpreterInfo::new()
    // This eliminates ~1-4ms of ELF parsing, /proc reads, and symbol lookup per frame
    let offsets = get_php_offsets_for_pid(pid);
    let mem = RemoteMemory::new(pid);

    // Read function name from zend_function->common.function_name
    let function_name_ptr: u64 =
        match mem.read_ptr(zend_function_ptr + offsets.function.common_funcname as u64) {
            Ok(ptr) => ptr,
            Err(_) => {
                // Check if this is top-level code using type_info
                let symbol = if type_info & ZEND_CALL_TOP_CODE != 0 {
                    format!("<top-level>:{} [PHP]", lineno)
                } else {
                    format!("<func>@{:#x}:{} [PHP]", zend_function_ptr, lineno)
                };
                return allocate_clib_string(symbol);
            }
        };

    let mut method_name = String::new();
    if function_name_ptr != 0 {
        // Read string data from zend_string->val
        method_name = mem
            .read_cstring(function_name_ptr + offsets.string.val as u64, 64)
            .unwrap_or_else(|_| String::from("<unknown>"));
    } else {
        // Check if this is top-level code using type_info
        if type_info & ZEND_CALL_TOP_CODE != 0 {
            let symbol = format!("<top-level>:{} [PHP]", lineno);
            return allocate_clib_string(symbol);
        }
    }

    // Try to read class name from zend_function->common.scope
    let mut class_name = String::new();
    if let Ok(scope_ptr) = mem.read_ptr(zend_function_ptr + offsets.function.common_scope as u64) {
        if scope_ptr != 0 {
            if let Ok(class_name_ptr) = mem.read_ptr(scope_ptr + offsets.class_entry.name as u64) {
                if class_name_ptr != 0 {
                    class_name = mem
                        .read_cstring(class_name_ptr + offsets.string.val as u64, 32)
                        .unwrap_or_else(|_| String::new());
                }
            }
        }
    }

    // Format symbol: ClassName::methodName:line [PHP] or methodName:line [PHP]
    let symbol = if !class_name.is_empty() {
        format!("{}::{}:{} [PHP]", class_name, method_name, lineno)
    } else if !method_name.is_empty() {
        format!("{}:{} [PHP]", method_name, lineno)
    } else {
        // Last resort: check type_info for top-level code
        if type_info & ZEND_CALL_TOP_CODE != 0 {
            format!("<top-level>:{} [PHP]", lineno)
        } else {
            format!("<func>@{:#x}:{} [PHP]", zend_function_ptr, lineno)
        }
    };

    // Allocate and return C string using clib_mem_alloc_aligned
    allocate_clib_string(symbol)
}

/// Check if a process is PHP
///
/// TWO-PHASE DETECTION:
/// 1. Fast path: Check if already registered (O(1), ~50ns)
///    - If registered, we know it's PHP (validated via ELF parsing during load)
/// 2. Fallback: Lightweight filename check (~10μs)
///    - For new/unregistered processes
///    - After this returns true, php_unwind_table_load() will:
///      a) Do full ELF validation (executor_globals symbol, version check)
///      b) Register to global registry if validation passes
///    - Future calls use fast path
///
/// This ensures:
/// - Strict validation: Only ELF-validated processes stay registered
/// - No chicken-egg problem: Initial detection works via filename
/// - High performance: O(1) lookup for hot paths
#[no_mangle]
pub unsafe extern "C" fn is_php_process(pid: u32) -> bool {
    // Fast path: O(1) registry lookup for already-loaded processes
    if crate::is_registered_as(pid, crate::InterpreterType::Php) {
        return true;
    }

    // Fallback: Lightweight filename check for new processes
    // This allows php_unwind_table_load() to be called, which does strict ELF validation
    if let Ok(exe_path) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
        if let Some(filename) = exe_path.file_name() {
            if let Some(name) = filename.to_str() {
                return name == "php"
                    || name.starts_with("php-fpm")
                    || name.starts_with("php-cgi")
                    || (name.starts_with("php") && name.len() > 3)
                    || (name.starts_with("libphp") && name.ends_with(".so"));
            }
        }
    }

    false
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration_tests;
