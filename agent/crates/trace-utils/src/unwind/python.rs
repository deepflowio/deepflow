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
    utils::{bpf_delete_elem, bpf_update_elem, get_errno, IdGenerator, BPF_ANY},
};

fn error_not_python(pid: u32) -> Error {
    Error::BadInterpreterType(pid, "python")
}

fn error_not_supported_version(pid: u32, version: Version) -> Error {
    Error::BadInterpreterVersion(pid, "python", version)
}

struct MappedFile {
    path: PathBuf,
    contents: Vec<u8>,
    mem_start: u64,
}

impl MappedFile {
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

    const VERSION_REGEX_STR: &'static str =
        r"((2|3)\.(3|4|5|6|7|8|9|10|11|12|13)(\.\d{1,2})?)((a|b|c|rc)\d{1,2})?\+?";
    // parse captures of previous regex
    fn parse_version(cap: regex::Captures) -> Option<Version> {
        Some(Version::new(
            cap.get(2)?.as_str().parse().ok()?,
            cap.get(3)?.as_str().parse().ok()?,
            cap.get(4)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or_default(),
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
                None => debug!(
                    "Cannot find python version from file {}",
                    self.path.display()
                ),
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

    // Adding symbol address with so base address seemed ok at the moment, but not sure if it's always correct
    // Mark this function as dead code for now
    #[allow(dead_code)]
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
}

struct Interpreter {
    pid: u32,
    exe: MappedFile,
    lib: Option<MappedFile>,
    version: Version,
}

impl Interpreter {
    // From parca-agent code: https://github.com/parca-dev/parca-agent/blob/18aade29250e8ee4145777006f287540694b887d/pkg/runtime/python/python.go#L32
    //
    // Python symbols to look for:
    //
    //      2.7:`Py_Main`
    //      3.2:`Py_Main`
    //      3.3:`Py_Main`
    //      3.4:`Py_Main`
    //      3.5:`Py_Main`
    //      3.6:`Py_Main`
    //      3.7:`_Py_UnixMain`
    //      3.8:`Py_BytesMain`
    //      3.9:`Py_BytesMain`
    //      3.10:`Py_BytesMain`
    //      3.11:`Py_BytesMain`
    const EXE_SYMBOLS: [&'static str; 3] = ["Py_Main", "_Py_UnixMain", "Py_BytesMain"];

    const RUNTIME_SYMBOL: &'static str = "_PyRuntime";
    const THREAD_STATE_SYMBOL: &'static str = "_PyThreadState_Current";
    const LIB_SYMBOLS: [&'static str; 2] = [Self::RUNTIME_SYMBOL, Self::THREAD_STATE_SYMBOL];

    fn new(pid: u32, exe: &MemoryArea, lib: Option<&MemoryArea>) -> Result<Self> {
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
        if !Self::is_python(&mut exe, lib.as_mut())? {
            return Err(error_not_python(pid));
        }
        // extract python version from executable and library name which is simple and probably good enough
        let mut version = None;
        for file in [Some(&exe), lib.as_ref()] {
            if let Some(v) = file.and_then(|f| f.version()) {
                version.replace(v);
            }
        }
        if let Some(v) = version {
            // TODO: Support other python versions
            if !VersionReq::parse(">=3.10.0, <3.11.0").unwrap().matches(&v) {
                return Err(error_not_supported_version(pid, v));
            }

            return Ok(Self {
                pid,
                exe,
                lib,
                version: v,
            });
        }
        warn!(
            "Cannot find python version from file {}",
            exe.path.display()
        );
        if let Some(f) = lib.as_ref() {
            warn!("Cannot find python version from file {}", f.path.display());
        }
        Err(error_not_python(pid))
    }

    fn is_python(exe: &mut MappedFile, lib: Option<&mut MappedFile>) -> Result<bool> {
        if exe
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.contains("python"))
            .unwrap_or(false)
        {
            exe.has_any_symbols(&Self::EXE_SYMBOLS)
        } else if let Some(lib) = lib {
            lib.has_any_symbols(&Self::LIB_SYMBOLS)
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

    fn thread_state_address(&mut self) -> Result<u64> {
        if !VersionReq::parse(">=3.7.0").unwrap().matches(&self.version) {
            return Err(error_not_supported_version(self.pid, self.version.clone()));
        }

        if let Some(addr) = self.find_symbol_address(Self::RUNTIME_SYMBOL)? {
            return Ok(addr + PY310_INITIAL_STATE.tstate_current);
        }
        Err(error_not_supported_version(self.pid, self.version.clone()))
    }
}

pub struct InterpreterInfo {
    pub version: Version,
    pub thread_address: u64,
}

impl InterpreterInfo {
    pub fn new(pid: u32) -> Result<Self> {
        trace!("find interpreter info for process#{pid}");
        let exe_path: PathBuf = ["/proc", &pid.to_string(), "exe"].iter().collect();
        let exe_path = fs::read_link(&exe_path)?;
        let exe_path_str = exe_path.to_str();

        let mm = get_memory_mappings(pid)?;
        let Some(exe_area) = mm.iter().find(|m| Some(m.path.as_str()) == exe_path_str) else {
            warn!("Process#{pid} executable path not in maps");
            return Err(error_not_python(pid));
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
            thread_address: intp.thread_state_address()?,
        })
    }

    thread_local! {
        static LIB_REGEX: OnceCell<Regex> = OnceCell::new();
    }

    fn match_lib(path: &str) -> bool {
        Self::LIB_REGEX.with(|r| {
            r.get_or_init(|| Regex::new(r"/libpython\d.\d\d?(m|d|u)?.so").unwrap())
                .is_match(path)
        })
    }
}

pub struct InitialState {
    tstate_current: u64,
}

const PY310_INITIAL_STATE: &InitialState = &InitialState {
    tstate_current: 568,
};

#[repr(C)]
pub struct PythonUnwindInfo {
    pub thread_state_address: u64,
    pub offsets_id: u8,
}

#[repr(C)]
pub struct PythonOffsets {
    pub cframe: PyCframe,
    pub code_object: PyCodeObject,
    pub frame_object: PyFrameObject,
    pub interpreter_frame: PyInterpreterFrame,
    pub interpreter_state: PyInterpreterState,
    pub object: PyObject,
    pub runtime_state: PyRuntimeState,
    pub string: PyString,
    pub thread_state: PyThreadState,
    pub tuple_object: PyTupleObject,
    pub type_object: PyTypeObject,
}

#[repr(C)]
pub struct PyCframe {
    pub current_frame: i64,
}

#[repr(C)]
pub struct PyCodeObject {
    pub co_filename: i64,
    pub co_firstlineno: i64,
    pub co_name: i64,
    pub co_varnames: i64,
}

#[repr(C)]
pub struct PyFrameObject {
    pub f_back: i64,
    pub f_code: i64,
    pub f_lineno: i64,
    pub f_localsplus: i64,
}

#[repr(C)]
pub struct PyInterpreterFrame {
    pub owner: i64,
}

#[repr(C)]
pub struct PyInterpreterState {
    pub tstate_head: i64,
}

#[repr(C)]
pub struct PyObject {
    pub ob_type: i64,
}

#[repr(C)]
pub struct PyRuntimeState {
    pub interp_main: i64,
}

#[repr(C)]
pub struct PyString {
    pub data: i64,
    pub size: i64,
}

#[repr(C)]
pub struct PyThreadState {
    pub cframe: i64,
    pub frame: i64,
    pub interp: i64,
    pub native_thread_id: i64,
    pub next: i64,
    pub thread_id: i64,
}

#[repr(C)]
pub struct PyTupleObject {
    pub ob_item: i64,
}

#[repr(C)]
pub struct PyTypeObject {
    pub tp_name: i64,
}

const PY310_OFFSETS: &PythonOffsets = &PythonOffsets {
    cframe: PyCframe { current_frame: 0 },
    code_object: PyCodeObject {
        co_filename: 104,
        co_firstlineno: 40,
        co_name: 112,
        co_varnames: 72,
    },
    frame_object: PyFrameObject {
        f_back: 24,
        f_code: 32,
        f_lineno: 100,
        f_localsplus: 352,
    },
    interpreter_frame: PyInterpreterFrame { owner: -1 },
    interpreter_state: PyInterpreterState { tstate_head: 8 },
    object: PyObject { ob_type: 8 },
    runtime_state: PyRuntimeState { interp_main: -1 },
    string: PyString { data: 48, size: -1 },
    thread_state: PyThreadState {
        cframe: -1,
        frame: 24,
        interp: 16,
        native_thread_id: -1,
        next: 8,
        thread_id: 176,
    },
    tuple_object: PyTupleObject { ob_item: 24 },
    type_object: PyTypeObject { tp_name: 24 },
};

#[derive(Default)]
pub struct PythonUnwindTable {
    id_gen: IdGenerator,
    loaded_offsets: HashMap<Version, u8>,

    unwind_info_map_fd: i32,
    offsets_map_fd: i32,
}

impl PythonUnwindTable {
    pub unsafe fn new(unwind_info_map_fd: i32, offsets_map_fd: i32) -> Self {
        Self {
            unwind_info_map_fd,
            offsets_map_fd,
            ..Default::default()
        }
    }

    pub unsafe fn load(&mut self, pid: u32) {
        trace!("load python unwind info for process#{pid}");
        let info = match InterpreterInfo::new(pid) {
            Ok(info) => info,
            Err(e) => {
                trace!("loading python interpreter info for process#{pid} has error: {e}");
                return;
            }
        };
        let req = VersionReq::parse(">=3.10.0, <3.11.0").unwrap();
        if !req.matches(&info.version) {
            debug!("python version {} is not supported", info.version);
            return;
        }

        let key = Version::new(info.version.major, info.version.minor, 0);
        let offsets_id = match self.loaded_offsets.get(&key) {
            Some(id) => *id,
            None => {
                let id = self.id_gen.acquire();
                // FIXME: handle other python versions
                if self.update_offsets_map(id as u8, &PY310_OFFSETS) != 0 {
                    self.id_gen.release(id);
                    return;
                }
                self.loaded_offsets.insert(key, id as u8);
                id as u8
            }
        };
        let info = PythonUnwindInfo {
            thread_state_address: info.thread_address,
            offsets_id,
        };
        self.update_unwind_info_map(pid, &info);
    }

    pub unsafe fn unload(&mut self, pid: u32) {
        trace!("unload python unwind info for process#{pid}");
        self.delete_unwind_info_map(pid);
    }

    unsafe fn update_unwind_info_map(&self, pid: u32, info: &PythonUnwindInfo) -> i32 {
        trace!("update python unwind info for process#{pid}");
        unsafe {
            let value = slice::from_raw_parts(
                info as *const PythonUnwindInfo as *const u8,
                mem::size_of::<PythonUnwindInfo>(),
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
                    libc::E2BIG => warn!("update python unwind info for process#{pid} failed: try increasing python_unwind_info_map_size"),
                    libc::ENOMEM => warn!("update python unwind info for process#{pid} failed: cannot allocate memory"),
                    _ => warn!("update python unwind info for process#{pid} failed: bpf_update_elem() returned {errno}"),
                }
            }
            ret
        }
    }

    unsafe fn delete_unwind_info_map(&self, pid: u32) -> i32 {
        trace!("delete python unwind info for process#{pid}");
        unsafe {
            let ret = bpf_delete_elem(self.unwind_info_map_fd, &pid as *const u32 as *const c_void);
            if ret != 0 {
                let errno = get_errno();
                // ignoring non exist error
                if errno != libc::ENOENT {
                    warn!(
                        "delete python unwind info for process#{pid} failed: bpf_delete_elem() returned {errno}"
                    );
                }
            }
            ret
        }
    }

    unsafe fn update_offsets_map(&self, id: u8, offsets: &PythonOffsets) -> i32 {
        trace!("update python offsets#{id}");
        unsafe {
            let value = slice::from_raw_parts(
                offsets as *const PythonOffsets as *const u8,
                mem::size_of::<PythonOffsets>(),
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
                    libc::E2BIG => warn!(
                        "update python offsets#{id} failed: try increasing python_offsets_map_size"
                    ),
                    libc::ENOMEM => {
                        warn!("update python offsets#{id} failed: cannot allocate memory")
                    }
                    _ => warn!(
                        "update python offsets#{id} failed: bpf_update_elem() returned {errno}"
                    ),
                }
            }
            ret
        }
    }
}

const PYEVAL_FNAME: &'static str = "_PyEval_EvalFrameDefault";
const LIB_PYEVAL_FNAME: &'static str = "[l] _PyEval_EvalFrameDefault";

pub const INCOMPLETE_PYTHON_STACK: &'static str = "[lost] incomplete python c stack";

#[no_mangle]
pub unsafe extern "C" fn merge_python_stacks(
    trace_str: *mut c_void,
    len: usize,
    i_trace: *const c_void,
    u_trace: *const c_void,
) -> usize {
    let Ok(i_trace) = CStr::from_ptr(i_trace as *const libc::c_char).to_str() else {
        return 0;
    };
    let Ok(u_trace) = CStr::from_ptr(u_trace as *const libc::c_char).to_str() else {
        return 0;
    };

    let mut trace = Vec::with_capacity(len);

    let mut n_py_frames = i_trace.split(";").count();
    if i_trace.starts_with("<module>") {
        n_py_frames -= 1; // <module> does not count
    }
    let n_eval_frames = u_trace
        .split(";")
        .filter(|c_func| *c_func == PYEVAL_FNAME || *c_func == LIB_PYEVAL_FNAME)
        .count();

    if n_eval_frames == 0 {
        // native stack not correctly unwinded, just put it on top of python frames
        let _ = write!(
            &mut trace,
            "{};{};{}",
            i_trace, INCOMPLETE_PYTHON_STACK, u_trace
        );
    } else if n_py_frames == n_eval_frames {
        // no native stack
        let _ = write!(&mut trace, "{}", i_trace);
    } else if n_py_frames == n_eval_frames - 1 {
        // python calls native, just put everything after the last _PyEval on top of python frames (including the semicolon)
        let loc = u_trace.rfind(PYEVAL_FNAME).unwrap() + PYEVAL_FNAME.len();
        let _ = write!(&mut trace, "{}{}", i_trace, &u_trace[loc..]);
    } else {
        let _ = write!(
            &mut trace,
            "{};{};{}",
            i_trace, INCOMPLETE_PYTHON_STACK, u_trace
        );
    }

    trace_str.write_bytes(0, len);
    let written = trace.len();
    std::ptr::copy_nonoverlapping(trace.as_ptr(), trace_str as *mut u8, written);
    written
}

#[no_mangle]
pub unsafe extern "C" fn is_python_process(pid: u32) -> bool {
    InterpreterInfo::new(pid).is_ok()
}
