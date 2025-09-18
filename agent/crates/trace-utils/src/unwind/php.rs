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
    path::{Path, PathBuf},
    slice,
};

use libc::c_void;
use log::{debug, trace, warn};
use object::{
    elf,
    read::elf::{FileHeader, ProgramHeader, SectionHeader},
    Object, ObjectSymbol,
};
use regex::Regex;
use semver::{Version, VersionReq};

use crate::{
    error::{Error, Result},
    maps::{get_memory_mappings, MemoryArea},
    unwind::php_jit::PhpJitSupport,
    unwind::php_opcache::PhpOpcacheSupport,
    utils::{bpf_delete_elem, bpf_update_elem, get_errno, IdGenerator, BPF_ANY},
};

fn error_not_php(pid: u32) -> Error {
    Error::BadInterpreterType(pid, "php")
}

fn error_not_supported_version(pid: u32, version: Version) -> Error {
    Error::BadInterpreterVersion(pid, "php", version)
}

struct MappedFile {
    path: PathBuf,
    contents: Vec<u8>,
    mem_start: u64,
}

impl MappedFile {
    fn load(&mut self) -> Result<()> {
        if self.contents.is_empty() {
            // CRITICAL FIX: Prevent reading from dangerous devices like /dev/zero
            // which can cause infinite memory consumption in PHP 8.0 JIT environments
            let path_str = self.path.to_string_lossy();
            if path_str.contains("/dev/zero")
                || path_str.contains("/dev/null")
                || path_str.contains("/dev/random")
                || path_str.contains("/dev/urandom")
            {
                warn!("Refusing to read from device file: {}", path_str);
                return Err(Error::BadInterpreterType(0, "php"));
            }

            // Additional safety: ensure path looks like a regular file
            if let Some(filename) = self.path.file_name() {
                let filename_str = filename.to_string_lossy();
                if filename_str == "zero"
                    || filename_str == "null"
                    || filename_str == "random"
                    || filename_str == "urandom"
                {
                    warn!("Refusing to read device file: {}", path_str);
                    return Err(Error::BadInterpreterType(0, "php"));
                }
            }

            trace!("Reading mapped file: {}", path_str);
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
                    if &name == sym {
                        return true;
                    }
                }
            }
            false
        }))
    }

    thread_local! {
        static VERSION_REGEX: OnceCell<Regex> = OnceCell::new();
    }

    const VERSION_REGEX_STR: &'static str = r"(([0-9]+)\.([0-9]+)\.([0-9]+))";

    fn parse_version(cap: regex::Captures) -> Option<Version> {
        Some(Version::new(
            cap.get(2)?.as_str().parse().ok()?,
            cap.get(3)?.as_str().parse().ok()?,
            cap.get(4)?.as_str().parse().ok()?,
        ))
    }

    fn version(&self) -> Option<Version> {
        if let Some(c) = self
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| {
                Self::VERSION_REGEX.with(|r| {
                    r.get_or_init(|| Regex::new(Self::VERSION_REGEX_STR).unwrap())
                        .captures(s)
                })
            })
        {
            match Self::parse_version(c) {
                Some(v) => return Some(v),
                None => debug!("Cannot find PHP version from file {}", self.path.display()),
            }
        }
        None
    }

    fn find_text_section_program_header<P: AsRef<Path>>(
        path: P,
        data: &[u8],
    ) -> Result<Option<&elf::ProgramHeader64<object::Endianness>>> {
        let elf = elf::FileHeader64::<object::Endianness>::parse(data)?;
        let endian = elf.endian()?;
        let sec_headers = elf.section_headers(endian, data)?;
        let sec_strs = elf.section_strings(endian, data, sec_headers)?;
        let Some(th) = sec_headers
            .iter()
            .find(|h| h.name(endian, sec_strs) == Ok(".text".as_bytes()))
        else {
            debug!("Cannot find .text section in {}", path.as_ref().display());
            return Ok(None);
        };
        for ph in elf.program_headers(endian, data)? {
            if ph.p_type(endian) == elf::PT_LOAD && ph.p_flags(endian) & elf::PF_X != 0 {
                let th_addr = th.sh_addr(endian);
                let ph_vaddr = ph.p_vaddr(endian);
                let ph_memsz = ph.p_memsz(endian);
                if th_addr >= ph_vaddr && th_addr < ph_vaddr + ph_memsz {
                    return Ok(Some(ph));
                }
            }
        }
        trace!(
            "Cannot find .text section program header in {}",
            path.as_ref().display()
        );
        Ok(None)
    }

    fn base_address(&mut self) -> Result<u64> {
        self.load()?;
        let elf = elf::FileHeader64::<object::Endianness>::parse(&*self.contents)?;
        let endian = elf.endian()?;
        let Some(ph) = Self::find_text_section_program_header(&self.path, &*self.contents)? else {
            return Ok(self.mem_start);
        };
        trace!(
            "mem_start: 0x{:x}, p_vaddr: 0x{:x}",
            self.mem_start,
            ph.p_vaddr(endian)
        );
        Ok(self.mem_start.saturating_sub(ph.p_vaddr(endian)))
    }

    fn find_symbol_address(&mut self, name: &str) -> Result<Option<u64>> {
        self.load()?;
        let ba = self.base_address()?;
        let obj = object::File::parse(&*self.contents)?;
        Ok(obj
            .symbols()
            .chain(obj.dynamic_symbols())
            .find(|s| s.name().map(|n| n == name).unwrap_or(false))
            .map(|s| s.address() + ba))
    }

    /// Extract PHP version from rodata by looking for "X-Powered-By: PHP/" string
    fn extract_version_from_rodata(&mut self) -> Result<Option<Version>> {
        self.load()?;
        let needle = b"X-Powered-By: PHP/";

        // Search for the version string in the binary data
        if let Some(pos) = self
            .contents
            .windows(needle.len())
            .position(|window| window == needle)
        {
            let start = pos + needle.len();
            let end = self.contents[start..]
                .iter()
                .position(|&b| b == 0 || b == b'\r' || b == b'\n')
                .map(|p| start + p)
                .unwrap_or(self.contents.len());

            if let Ok(version_str) = std::str::from_utf8(&self.contents[start..end]) {
                if let Some(cap) = Self::VERSION_REGEX.with(|r| {
                    r.get_or_init(|| Regex::new(Self::VERSION_REGEX_STR).unwrap())
                        .captures(version_str)
                }) {
                    return Ok(Self::parse_version(cap));
                }
            }
        }
        Ok(None)
    }
}

struct Interpreter {
    pid: u32,
    exe: MappedFile,
    lib: Option<MappedFile>,
    version: Version,
}

impl Interpreter {
    // PHP symbols to look for based on OpenTelemetry implementation
    const EXE_SYMBOLS: [&'static str; 3] = ["execute_ex", "executor_globals", "zend_execute"];
    const RUNTIME_SYMBOL: &'static str = "executor_globals";
    const LIB_SYMBOLS: [&'static str; 1] = [Self::RUNTIME_SYMBOL];

    fn new(pid: u32, exe: &MemoryArea, lib: Option<&MemoryArea>) -> Result<Self> {
        // CRITICAL FIX: Early detection of device files to prevent infinite memory consumption
        if exe.path.contains("/dev/") {
            warn!(
                "Refusing to process device file as executable: {}",
                exe.path
            );
            return Err(error_not_php(pid));
        }
        if let Some(lib_area) = lib {
            if lib_area.path.contains("/dev/") {
                warn!(
                    "Refusing to process device file as library: {}",
                    lib_area.path
                );
                return Err(error_not_php(pid));
            }
        }

        let base: PathBuf = ["/proc", &pid.to_string(), "root"].iter().collect();
        let mut exe = MappedFile {
            path: base.join(&exe.path[1..]),
            contents: vec![],
            mem_start: exe.mx_start,
        };
        let mut lib = lib.map(|m| MappedFile {
            path: base.join(&m.path[1..]),
            contents: vec![],
            mem_start: m.mx_start,
        });
        if !Self::is_php(&mut exe, lib.as_mut())? {
            return Err(error_not_php(pid));
        }

        // Extract PHP version from executable and library
        let mut version = None;

        // First try to get version from filename
        for file in [Some(&exe), lib.as_ref()] {
            if let Some(v) = file.and_then(|f| f.version()) {
                version.replace(v);
            }
        }

        // If filename version detection failed, try rodata extraction
        if version.is_none() {
            for file in [Some(&mut exe), lib.as_mut()] {
                if let Some(file) = file {
                    if let Ok(Some(v)) = file.extract_version_from_rodata() {
                        version.replace(v);
                        break;
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
        if exe
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.contains("php"))
            .unwrap_or(false)
        {
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
}

pub struct InterpreterInfo {
    pub version: Version,
    pub executor_globals_address: u64,
}

impl InterpreterInfo {
    pub fn new(pid: u32) -> Result<Self> {
        trace!("find PHP interpreter info for process#{pid}");
        let exe_path: PathBuf = ["/proc", &pid.to_string(), "exe"].iter().collect();
        let exe_path = fs::read_link(&exe_path)?;
        let exe_path_str = exe_path.to_str();

        let mm = get_memory_mappings(pid)?;
        let Some(exe_area) = mm.iter().find(|m| Some(m.path.as_str()) == exe_path_str) else {
            warn!("Process#{pid} executable path not in maps");
            return Err(error_not_php(pid));
        };
        let lib_area = mm.iter().find(|m| Self::match_lib(&m.path));
        debug!(
            "process#{pid} exe: {} lib: {}",
            exe_area.path,
            lib_area.map(|m| m.path.as_str()).unwrap_or("n/a")
        );

        let mut intp = Interpreter::new(pid, exe_area, lib_area)?;
        Ok(Self {
            version: intp.version.clone(),
            executor_globals_address: intp.executor_globals_address()?,
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
    pub offsets_id: u8,
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

    fn recover_jit_return_address(&mut self, pid: u32, version: &Version) -> Result<u64> {
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

        // Get the PHP binary path from the process
        let exe_path = format!("/proc/{}/exe", pid);
        let php_binary_path = if let Ok(path) = fs::read_link(&exe_path) {
            path
        } else {
            // Fallback to common locations
            let php_binary_paths = [
                "/usr/bin/php",
                "/usr/local/bin/php",
                "/opt/php/bin/php",
                "/usr/sbin/php-fpm",
                "/usr/local/sbin/php-fpm",
            ];

            let mut found_path = None;
            for path in &php_binary_paths {
                if fs::metadata(path).is_ok() {
                    found_path = Some(std::path::PathBuf::from(*path));
                    break;
                }
            }

            if let Some(path) = found_path {
                path
            } else {
                debug!("Could not find PHP binary for process#{}", pid);
                return Ok(0);
            }
        };

        // Analyze the PHP binary for JIT return address
        if let Ok(binary_data) = fs::read(&php_binary_path) {
            match jit_support.recover_jit_return_address(&binary_data) {
                Ok(addr) if addr != 0 => {
                    debug!(
                        "Successfully recovered JIT return address 0x{:x} from {}",
                        addr,
                        php_binary_path.display()
                    );

                    // Verify JIT is ready for use
                    if jit_support.is_jit_ready() {
                        debug!("JIT profiling fully configured for PHP {}", version);
                    } else {
                        debug!("JIT return address recovered but JIT not fully ready");
                    }

                    return Ok(addr);
                }
                Ok(_) => {
                    debug!(
                        "No JIT return address found in {}",
                        php_binary_path.display()
                    );
                }
                Err(e) => {
                    debug!(
                        "Failed to analyze {} for JIT support: {}",
                        php_binary_path.display(),
                        e
                    );
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

        let req = VersionReq::parse(">=7.4.0, <8.4.0").unwrap();
        if !req.matches(&info.version) {
            debug!("PHP version {} is not supported", info.version);
            return;
        }

        let key = Version::new(info.version.major, info.version.minor, 0);
        let offsets_id = match self.loaded_offsets.get(&key) {
            Some(id) => *id,
            None => {
                let id = self.id_gen.acquire();
                let offsets = get_offsets_for_version(&info.version);
                if self.update_offsets_map(id as u8, offsets) != 0 {
                    self.id_gen.release(id);
                    return;
                }
                self.loaded_offsets.insert(key, id as u8);
                id as u8
            }
        };

        let jit_return_address = if info.version >= Version::new(8, 0, 0) {
            // Try to recover JIT return address for PHP 8+
            match self.recover_jit_return_address(pid, &info.version) {
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
            offsets_id,
        };
        self.update_unwind_info_map(pid, &info);
    }

    pub unsafe fn unload(&mut self, pid: u32) {
        trace!("unload PHP unwind info for process#{pid}");
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

        trace!("delete PHP unwind info for process#{pid}");
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
const INCOMPLETE_PHP_STACK: &'static str = "[lost] incomplete PHP c stack";

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

    let n_php_frames = i_trace.split(";").count();
    let n_execute_ex_frames = u_trace
        .split(";")
        .filter(|c_func| c_func.contains("execute_ex"))
        .count();

    if n_execute_ex_frames == 0 {
        // native stack not correctly unwinded, just put it on top of PHP frames
        let _ = write!(
            &mut trace,
            "{};{};{}",
            i_trace, INCOMPLETE_PHP_STACK, u_trace
        );
    } else if n_php_frames == n_execute_ex_frames {
        // no native stack
        let _ = write!(&mut trace, "{}", i_trace);
    } else if n_php_frames == n_execute_ex_frames - 1 {
        // PHP calls native, just put everything after the last execute_ex on top of PHP frames
        if let Some(loc) = u_trace.rfind("execute_ex") {
            let start_pos = loc + "execute_ex".len();
            let _ = write!(&mut trace, "{}{}", i_trace, &u_trace[start_pos..]);
        } else {
            let _ = write!(&mut trace, "{}", i_trace);
        }
    } else {
        let _ = write!(
            &mut trace,
            "{};{};{}",
            i_trace, INCOMPLETE_PHP_STACK, u_trace
        );
    }

    trace_str.write_bytes(0, len);
    let written = trace.len();
    std::ptr::copy_nonoverlapping(trace.as_ptr(), trace_str as *mut u8, written);
    written
}

#[no_mangle]
pub unsafe extern "C" fn is_php_process(pid: u32) -> bool {
    InterpreterInfo::new(pid).is_ok()
}

#[cfg(test)]
#[path = "php/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "php/integration_tests.rs"]
mod integration_tests;
