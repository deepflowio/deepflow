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
    collections::HashMap,
    ffi::CStr,
    mem::{self, MaybeUninit},
    ptr, slice, str,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use libc::{c_char, c_int, c_void, iovec};
use log::{debug, info, trace, warn};

use crate::maps::get_memory_mappings;
use crate::utils::{bpf_delete_elem, bpf_update_elem, get_errno, IdGenerator, BPF_ANY};

const LANG_LUA: u32 = 1 << 0;
const LANG_LUAJIT: u32 = 1 << 1;
pub const LUA_RUNTIME_VERSION_LEN: usize = 32;
pub const LUA_RUNTIME_DETECT_METHOD_LEN: usize = 256;
pub const LUA_RUNTIME_PATH_LEN: usize = 1024;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LuaRuntimeInfo {
    pub kind: u32,                              // 0 = none, 1 = Lua, 2 = LuaJIT
    pub version: [u8; LUA_RUNTIME_VERSION_LEN], // e.g. "5.4", "5.3", "2.1"
    pub detection_method: [u8; LUA_RUNTIME_DETECT_METHOD_LEN],
    pub path: [u8; LUA_RUNTIME_PATH_LEN],
}

fn trim_nul(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(idx) => &bytes[..idx],
        None => bytes,
    }
}

fn bytes_to_str(bytes: &[u8]) -> &str {
    match str::from_utf8(trim_nul(bytes)) {
        Ok(s) => s,
        Err(_) => "",
    }
}

impl LuaRuntimeInfo {
    fn version_str(&self) -> &str {
        bytes_to_str(&self.version)
    }

    fn detection_method_str(&self) -> &str {
        bytes_to_str(&self.detection_method)
    }

    fn path_str(&self) -> &str {
        bytes_to_str(&self.path)
    }
}

// --------- C FFI surface ---------

#[no_mangle]
pub extern "C" fn is_lua_process(pid: u32) -> i32 {
    if pid <= 0 {
        return 0;
    }

    // Fast path: once the unwind table has been loaded successfully for a PID,
    // it registers the PID so hot callers (e.g. stack stringifier) avoid scanning
    // `/proc/<pid>/maps` on every sample.
    if crate::is_registered_as(pid, crate::InterpreterType::Lua) {
        return 1;
    }

    detect_runtime_cached(pid as u32).is_some() as i32
}

#[no_mangle]
pub unsafe extern "C" fn lua_detect(pid: u32, out: *mut LuaRuntimeInfo) -> i32 {
    if pid <= 0 || out.is_null() {
        return -1;
    }

    match detect_runtime_cached(pid as u32) {
        Some(info) => {
            {
                *out = info;
            }
            0
        }
        None => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn merge_lua_stacks(
    trace_str: *mut c_void,
    len: usize,
    u_trace: *const c_void,
    i_trace: *const c_void,
) -> usize {
    if trace_str.is_null() || len == 0 {
        return 0;
    }

    let user = if u_trace.is_null() {
        ""
    } else {
        match CStr::from_ptr(u_trace as *const c_char).to_str() {
            Ok(s) => s,
            Err(_) => "",
        }
    };

    let lua = if i_trace.is_null() {
        ""
    } else {
        match CStr::from_ptr(i_trace as *const c_char).to_str() {
            Ok(s) => s,
            Err(_) => "",
        }
    };

    if user.is_empty() {
        return write_combined_output(trace_str, len, lua.as_bytes());
    }
    if lua.is_empty() {
        return write_combined_output(trace_str, len, user.as_bytes());
    }

    let lua_frames: Vec<&str> = lua.split(';').filter(|s| !s.is_empty()).collect();
    let mut lua_idx = 0usize;

    let mut merged: Vec<u8> = Vec::with_capacity(len);
    let mut first = true;

    // Lua execution alternates between native call frames (C functions inside the host
    // application) and interpreter frames that the VM keeps in its own data structures.
    // Our profiler captures these two views separately: the perf-collected user stack
    // reflects the native frames, while the interpreter unwind reconstructs the Lua frames.
    // Merging walks the native stack in order and substitutes each Lua VM placeholder with
    // the decoded interpreter frame, preserving any surrounding C frames.
    for frame in user.split(';').filter(|s| !s.is_empty()) {
        let should_replace = frame.starts_with("[unknown") || frame.starts_with("[unkown");
        if should_replace && lua_idx < lua_frames.len() {
            if !first {
                merged.push(b';');
            }
            merged.extend_from_slice(lua_frames[lua_idx].as_bytes());
            lua_idx += 1;
            first = false;
            continue;
        }

        if !first {
            merged.push(b';');
        }
        merged.extend_from_slice(frame.as_bytes());
        first = false;
    }

    while lua_idx < lua_frames.len() {
        if !first {
            merged.push(b';');
        }
        merged.extend_from_slice(lua_frames[lua_idx].as_bytes());
        lua_idx += 1;
        first = false;
    }

    write_combined_output(trace_str, len, &merged)
}

const TAG_BITS: u64 = 2;
const TAG_SHIFT: u64 = 64 - TAG_BITS;
const TAG_MASK: u64 = 0x3 << TAG_SHIFT;
const TAG_LUA: u64 = 0x0 << TAG_SHIFT;
const TAG_CFUNC: u64 = 0x1 << TAG_SHIFT;
const TAG_FFUNC: u64 = 0x2 << TAG_SHIFT;
const LUA_CHUNK_READ_MAX: usize = 4096;

#[derive(Clone, Copy, Default)]
struct LuaMapFds {
    lang_flags_fd: i32,
    unwind_info_fd: i32,
    lua_offsets_fd: i32,
    luajit_offsets_fd: i32,
}

static LUA_MAP_FDS: OnceLock<Mutex<LuaMapFds>> = OnceLock::new();

fn get_lua_map_fds() -> Option<LuaMapFds> {
    let fds = LUA_MAP_FDS.get_or_init(|| Mutex::new(LuaMapFds::default()));
    let guard = fds.lock().unwrap();
    if guard.lang_flags_fd < 0
        || guard.unwind_info_fd < 0
        || guard.lua_offsets_fd < 0
        || guard.luajit_offsets_fd < 0
    {
        None
    } else {
        Some(*guard)
    }
}

#[no_mangle]
pub extern "C" fn lua_set_map_fds(
    lang_flags_fd: i32,
    unwind_info_fd: i32,
    lua_offsets_fd: i32,
    luajit_offsets_fd: i32,
) {
    let fds = LUA_MAP_FDS.get_or_init(|| Mutex::new(LuaMapFds::default()));
    let mut guard = fds.lock().unwrap();
    *guard = LuaMapFds {
        lang_flags_fd,
        unwind_info_fd,
        lua_offsets_fd,
        luajit_offsets_fd,
    };
}

struct LuaLayoutCache {
    pid: i32,
    layout: Option<LayoutState>,
}

impl LuaLayoutCache {
    const fn new() -> Self {
        Self {
            pid: -1,
            layout: None,
        }
    }
}

static LUA_LAYOUT_CACHE: OnceLock<Mutex<LuaLayoutCache>> = OnceLock::new();

fn lua_cache() -> &'static Mutex<LuaLayoutCache> {
    LUA_LAYOUT_CACHE.get_or_init(|| Mutex::new(LuaLayoutCache::new()))
}

fn lua_layout_cache_remove(pid: u32) {
    let cache_lock = lua_cache();
    let mut cache = cache_lock.lock().unwrap();
    if cache.pid == pid as i32 {
        cache.pid = -1;
        cache.layout = None;
    }
}

extern "C" {
    fn bpf_lookup_elem(fd: c_int, key: *mut c_void, value: *mut c_void) -> c_int;
    fn resolve_addr(
        tracer: *mut c_void,
        pid: u32,
        is_start_idx: bool,
        address: u64,
        new_cache: bool,
        info_p: *mut c_void,
    ) -> *mut c_char;
    fn clib_mem_alloc_aligned(
        name: *const c_char,
        size: usize,
        align: u32,
        alloc_sz: *mut usize,
    ) -> *mut c_void;
    fn clib_mem_free(ptr: *mut c_void);
}

#[no_mangle]
pub unsafe extern "C" fn lua_format_folded_stack_trace(
    tracer: *mut c_void,
    pid: u32,
    frames: *const u64,
    frame_count: u32,
    new_cache: bool,
    info_p: *mut c_void,
    err_tag: *const c_char,
) -> *mut c_char {
    if frames.is_null() || frame_count == 0 {
        return ptr::null_mut();
    }

    let Some(layout) = refresh_lua_layout(pid) else {
        return ptr::null_mut();
    };

    let err_bytes = if err_tag.is_null() {
        b"[interpreter stack trace error]".to_vec()
    } else {
        CStr::from_ptr(err_tag).to_bytes().to_vec()
    };

    let raw = slice::from_raw_parts(frames, frame_count as usize);
    let mut buf_vec = Vec::with_capacity(frame_count as usize * 32);

    for &encoded in raw {
        if encoded == 0 {
            continue;
        }
        if buf_vec.is_empty() {
            if !decode_lua_frame(
                encoded,
                tracer,
                pid,
                new_cache,
                info_p,
                &layout,
                &err_bytes,
                &mut buf_vec,
            ) {
                buf_vec.clear();
            }
        } else {
            let len_before = buf_vec.len();
            buf_vec.push(b';');
            if !decode_lua_frame(
                encoded,
                tracer,
                pid,
                new_cache,
                info_p,
                &layout,
                &err_bytes,
                &mut buf_vec,
            ) {
                buf_vec.truncate(len_before);
            }
        }
    }

    if buf_vec.is_empty() {
        return ptr::null_mut();
    }

    let total_size = buf_vec.len() + 1;
    let name = CStr::from_bytes_with_nul(b"lua_folded_str\0").unwrap();
    let c_buf = clib_mem_alloc_aligned(name.as_ptr(), total_size, 0, ptr::null_mut::<usize>())
        as *mut c_char;
    if c_buf.is_null() {
        return ptr::null_mut();
    }

    let out = c_buf as *mut u8;
    ptr::copy_nonoverlapping(buf_vec.as_ptr(), out, buf_vec.len());
    ptr::write(out.add(buf_vec.len()), 0);

    c_buf
}

#[derive(Copy, Clone)]
enum LayoutState {
    Lua(LuaOfs),
    LuaJit(LjOfs),
}

unsafe fn refresh_lua_layout(pid: u32) -> Option<LayoutState> {
    let fds = get_lua_map_fds()?;
    let cache_lock = lua_cache();
    let mut cache = cache_lock.lock().unwrap();
    let pid_i32 = pid as i32;
    if cache.pid != pid_i32 {
        cache.pid = pid_i32;
        cache.layout = None;

        let pid_key = pid as u32;
        let flags = lookup_map_value::<u32>(fds.lang_flags_fd, pid_key).unwrap_or(0);
        if flags == 0 {
            return None;
        }

        let offsets_id = lookup_map_value::<LuaUnwindInfo>(fds.unwind_info_fd, pid_key)
            .map(|info| info.offsets_id as u32)
            .unwrap_or(0);

        if flags & LANG_LUAJIT != 0 {
            if let Some(ofs) = lookup_map_value::<LjOfs>(fds.luajit_offsets_fd, offsets_id) {
                cache.layout = Some(LayoutState::LuaJit(ofs));
            }
        } else if flags & LANG_LUA != 0 {
            if let Some(ofs) = lookup_map_value::<LuaOfs>(fds.lua_offsets_fd, offsets_id) {
                cache.layout = Some(LayoutState::Lua(ofs));
            }
        }
    }

    cache.layout
}

unsafe fn lookup_map_value<T: Copy>(fd: c_int, mut key: u32) -> Option<T> {
    if fd < 0 {
        return None;
    }
    let mut value = MaybeUninit::<T>::uninit();
    let ret = bpf_lookup_elem(
        fd,
        &mut key as *mut _ as *mut c_void,
        value.as_mut_ptr() as *mut c_void,
    );
    if ret == 0 {
        Some(value.assume_init())
    } else {
        None
    }
}

unsafe fn decode_lua_frame(
    encoded: u64,
    tracer: *mut c_void,
    pid: u32,
    new_cache: bool,
    info_p: *mut c_void,
    layout: &LayoutState,
    err_bytes: &[u8],
    out: &mut Vec<u8>,
) -> bool {
    let tag = encoded & TAG_MASK;
    if tag == TAG_LUA {
        let proto = encoded & !TAG_MASK;
        if proto == 0 {
            return false;
        }
        let mut chunk = [0u8; 128];
        let chunk_len = lua_decode_chunk_name(pid, proto, layout, &mut chunk);
        let line = lua_decode_first_line(pid, proto, layout);

        let line_bytes = line
            .map(|lno| lno.to_string())
            .unwrap_or_else(|| "?".to_string());

        if let Some(len) = chunk_len {
            out.extend_from_slice(b"L:");
            out.extend_from_slice(&chunk[..len]);
            out.extend_from_slice(b":");
            out.extend_from_slice(line_bytes.as_bytes());
        } else {
            out.extend_from_slice(b"L:line=");
            out.extend_from_slice(line_bytes.as_bytes());
        }
        return true;
    } else if tag == TAG_CFUNC {
        let addr = encoded & !TAG_MASK;
        let ptr = resolve_addr(tracer, pid, false, addr, new_cache, info_p);
        if ptr.is_null() {
            out.extend_from_slice(format!("C:0x{addr:016x}").as_bytes());
            return true;
        }
        let cstr = CStr::from_ptr(ptr);
        let bytes = cstr.to_bytes();
        let owned = if bytes.starts_with(b"[unknown") {
            format!("[unkown] C:0x{addr:016x}").into_bytes()
        } else {
            bytes.to_vec()
        };
        out.extend_from_slice(&owned);
        clib_mem_free(ptr as *mut c_void);
        return true;
    } else if tag == TAG_FFUNC {
        let ffid = encoded & !TAG_MASK;
        out.extend_from_slice(format!("builtin#{ffid}").as_bytes());
        return true;
    }

    out.extend_from_slice(err_bytes);
    true
}

unsafe fn lua_decode_chunk_name(
    pid: u32,
    proto: u64,
    layout: &LayoutState,
    dst: &mut [u8],
) -> Option<usize> {
    match layout {
        LayoutState::Lua(ofs) => lua_decode_lua_chunk_name(pid, proto, &ofs, dst),
        LayoutState::LuaJit(ofs) => lua_decode_luajit_chunk_name(pid, proto, &ofs, dst),
    }
}

unsafe fn lua_decode_lua_chunk_name(
    pid: u32,
    proto: u64,
    lua_ofs: &LuaOfs,
    dst: &mut [u8],
) -> Option<usize> {
    if dst.len() < 2 {
        return None;
    }

    // Read proto->source (TString*)
    let mut ts_ptr: usize = 0;
    read_value(pid, proto + lua_ofs.off_proto_source as u64, &mut ts_ptr)?;
    if ts_ptr == 0 {
        return None;
    }

    let max_copy = dst.len() - 1;
    if max_copy == 0 {
        return None;
    }

    let mut copy_len = LUA_CHUNK_READ_MAX.min(max_copy) as usize;
    if copy_len > 0 {
        read_bytes(
            pid,
            ts_ptr as u64 + lua_ofs.sizeof_tstring as u64,
            &mut dst[..copy_len],
        )?;
    }

    if let Some(zero_idx) = dst[..copy_len].iter().position(|&b| b == 0) {
        copy_len = zero_idx;
    }
    dst[copy_len] = 0;
    Some(copy_len)
}

unsafe fn lua_decode_luajit_chunk_name(
    pid: u32,
    proto: u64,
    lj_ofs: &LjOfs,
    dst: &mut [u8],
) -> Option<usize> {
    if dst.len() < 2 {
        return None;
    }

    let mut raw_ref = 0u64;
    read_value(
        pid,
        proto + lj_ofs.off_gcproto_chunkname as u64,
        &mut raw_ref,
    )?;

    let gcs_ptr = if lj_ofs.gc64 != 0 {
        raw_ref & ((1u64 << 47) - 1)
    } else {
        (raw_ref & 0xffff_ffff) as u64
    };
    if gcs_ptr == 0 {
        return None;
    }

    let mut len = 0u32;
    read_value(pid, gcs_ptr + lj_ofs.off_gcstr_len as u64, &mut len)?;

    let max_copy = dst.len() - 1;
    let mut copy_len = len.min(LUA_CHUNK_READ_MAX as u32) as usize;
    if copy_len > max_copy {
        copy_len = max_copy;
    }

    if copy_len > 0 {
        read_bytes(
            pid,
            gcs_ptr + lj_ofs.off_gcstr_data as u64,
            &mut dst[..copy_len],
        )?;
    }
    dst[copy_len] = 0;
    Some(copy_len)
}

unsafe fn lua_decode_first_line(pid: u32, proto: u64, layout: &LayoutState) -> Option<u32> {
    match layout {
        LayoutState::Lua(ofs) => {
            let mut line = 0i32;
            match read_value(pid, proto + ofs.off_proto_linedefined as u64, &mut line) {
                Some(()) if line > 0 => Some(line as u32),
                Some(()) => {
                    trace!(
                        "lua_decode_firstline: Lua proto line <= 0 (pid={pid}, proto=0x{proto:016x}, value={line})"
                    );
                    None
                }
                None => {
                    trace!(
                        "lua_decode_firstline: failed to read Lua line info (pid={pid}, proto=0x{proto:016x})"
                    );
                    None
                }
            }
        }
        LayoutState::LuaJit(ofs) => {
            let mut line = 0i32;
            match read_value(pid, proto + ofs.off_gcproto_firstline as u64, &mut line) {
                Some(()) if line > 0 => Some(line as u32),
                Some(()) => {
                    trace!(
                        "lua_decode_firstline: LuaJIT proto line <= 0 (pid={pid}, proto=0x{proto:016x}, value={line})"
                    );
                    None
                }
                None => {
                    trace!(
                        "lua_decode_firstline: failed to read LuaJIT line info (pid={pid}, proto=0x{proto:016x})"
                    );
                    None
                }
            }
        }
    }
}

unsafe fn read_value<T: Copy>(pid: u32, addr: u64, out: &mut T) -> Option<()> {
    let buf = slice::from_raw_parts_mut(out as *mut T as *mut u8, mem::size_of::<T>());
    read_bytes(pid, addr, buf)
}

unsafe fn read_bytes(pid: u32, addr: u64, buf: &mut [u8]) -> Option<()> {
    if addr == 0 {
        return None;
    }
    let local = iovec {
        iov_base: buf.as_mut_ptr() as *mut c_void,
        iov_len: buf.len(),
    };
    let remote = iovec {
        iov_base: addr as usize as *mut c_void,
        iov_len: buf.len(),
    };
    let ret = libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0);
    (ret == buf.len() as isize).then_some(())
}

// --------- Lua unwind table plumbing ---------

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LuaUnwindInfo {
    pub offsets_id: u8,
    pub reserved: [u8; 7],
    pub state_address: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LuaOfs {
    pub features: u32,
    pub off_l_ci: u32,
    pub off_l_base_ci: u32,
    pub off_l_end_ci: u32,
    pub off_ci_func: u32,
    pub off_ci_top: u32,
    pub off_ci_savedpc: u32,
    pub off_ci_prev: u32,
    pub off_tvalue_tt: u32,
    pub off_tvalue_val: u32,
    pub off_closure_isc: u32,
    pub off_lclosure_p: u32,
    pub off_cclosure_f: u32,
    pub off_proto_source: u32,
    pub off_proto_linedefined: u32,
    pub off_proto_code: u32,
    pub off_proto_sizecode: u32,
    pub off_proto_lineinfo: u32,
    pub off_proto_abslineinfo: u32,
    pub off_tstring_len: u32,
    pub sizeof_tstring: u32,
    pub sizeof_callinfo: u32,
    pub sizeof_tvalue: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LjOfs {
    pub fr2: u8,
    pub gc64: u8,
    pub pad: u16,
    pub tv_sz: u32,
    pub off_l_base: u32,
    pub off_l_stack: u32,
    pub off_gcproto_firstline: u32,
    pub off_gcproto_chunkname: u32,
    pub off_gcstr_data: u32,
    pub off_gcfunc_cfunc: u32,
    pub off_gcfunc_ffid: u32,
    pub off_gcfunc_pc: u32,
    pub off_gcproto_bc: u32,
    pub off_gcstr_len: u32,
    pub off_l_glref: u32,
    pub off_global_state_dispatchmode: u32,
}

#[cfg(target_arch = "aarch64")]
const LUA_51_OFFSETS: Option<LuaOfs> = Some(LuaOfs {
    features: LUA_FEAT_CI_ARRAY
        | LUA_FEAT_LINEINFO
        | LUA_FEAT_PC_INSTR_INDEX
        | LUA_FEAT_CLOSURE_ISC,
    off_l_ci: 40,
    off_l_base_ci: 80,
    off_l_end_ci: 72,
    off_ci_func: 8,
    off_ci_top: 0,
    off_ci_savedpc: 24,
    off_ci_prev: 0,
    off_tvalue_tt: 0,
    off_tvalue_val: 0,
    off_closure_isc: 10,
    off_lclosure_p: 32,
    off_cclosure_f: 32,
    off_proto_source: 64,
    off_proto_linedefined: 96,
    off_proto_code: 24,
    off_proto_sizecode: 80,
    off_proto_lineinfo: 0,
    off_proto_abslineinfo: 0,
    off_tstring_len: 0,
    sizeof_tstring: 16,
    sizeof_callinfo: 40,
    sizeof_tvalue: 24,
});

#[cfg(not(target_arch = "aarch64"))]
const LUA_51_OFFSETS: Option<LuaOfs> = None;

#[cfg(target_arch = "aarch64")]
const LUA_52_OFFSETS: Option<LuaOfs> = Some(LuaOfs {
    features: LUA_FEAT_CI_LINKED | LUA_FEAT_LINEINFO | LUA_FEAT_PC_INSTR_INDEX | LUA_FEAT_LCF,
    off_l_ci: 32,
    off_l_base_ci: 0,
    off_l_end_ci: 0,
    off_ci_func: 0,
    off_ci_top: 0,
    off_ci_savedpc: 56,
    off_ci_prev: 16,
    off_tvalue_tt: 8,
    off_tvalue_val: 0,
    off_closure_isc: 0,
    off_lclosure_p: 24,
    off_cclosure_f: 24,
    off_proto_source: 72,
    off_proto_linedefined: 104,
    off_proto_code: 24,
    off_proto_sizecode: 88,
    off_proto_lineinfo: 40,
    off_proto_abslineinfo: 0,
    off_tstring_len: 0,
    sizeof_tstring: 24,
    sizeof_callinfo: 80,
    sizeof_tvalue: 16,
});

#[cfg(not(target_arch = "aarch64"))]
const LUA_52_OFFSETS: Option<LuaOfs> = None;

#[cfg(target_arch = "aarch64")]
const LUA_53_OFFSETS: Option<LuaOfs> = Some(LuaOfs {
    features: LUA_FEAT_CI_LINKED | LUA_FEAT_LINEINFO | LUA_FEAT_PC_INSTR_INDEX | LUA_FEAT_LCF,
    off_l_ci: 32,
    off_l_base_ci: 0,
    off_l_end_ci: 0,
    off_ci_func: 0,
    off_ci_top: 8,
    off_ci_savedpc: 40,
    off_ci_prev: 16,
    off_tvalue_tt: 8,
    off_tvalue_val: 0,
    off_closure_isc: 0,
    off_lclosure_p: 24,
    off_cclosure_f: 24,
    off_proto_source: 104,
    off_proto_linedefined: 40,
    off_proto_code: 56,
    off_proto_sizecode: 24,
    off_proto_lineinfo: 72,
    off_proto_abslineinfo: 0,
    off_tstring_len: 0,
    sizeof_tstring: 24,
    sizeof_callinfo: 72,
    sizeof_tvalue: 16,
});

#[cfg(not(target_arch = "aarch64"))]
const LUA_53_OFFSETS: Option<LuaOfs> = None;

#[cfg(target_arch = "aarch64")]
const LUA_54_OFFSETS: Option<LuaOfs> = Some(LuaOfs {
    features: LUA_FEAT_CI_LINKED | LUA_FEAT_LINEINFO | LUA_FEAT_PC_INSTR_INDEX | LUA_FEAT_LCF,
    off_l_ci: 32,
    off_l_base_ci: 0,
    off_l_end_ci: 0,
    off_ci_func: 0,
    off_ci_top: 8,
    off_ci_savedpc: 32,
    off_ci_prev: 16,
    off_tvalue_tt: 8,
    off_tvalue_val: 0,
    off_closure_isc: 0,
    off_lclosure_p: 24,
    off_cclosure_f: 24,
    off_proto_source: 112,
    off_proto_linedefined: 44,
    off_proto_code: 63,
    off_proto_sizecode: 24,
    off_proto_lineinfo: 88,
    off_proto_abslineinfo: 0,
    off_tstring_len: 0,
    sizeof_tstring: 32,
    sizeof_callinfo: 64,
    sizeof_tvalue: 16,
});

#[cfg(not(target_arch = "aarch64"))]
const LUA_54_OFFSETS: Option<LuaOfs> = None;

#[cfg(target_arch = "aarch64")]
const LJ_OFFSETS_21: Option<LjOfs> = Some(LjOfs {
    fr2: 1,
    gc64: 1,
    pad: 0,
    tv_sz: 8,
    off_l_base: 32,
    off_l_stack: 56,
    off_gcproto_firstline: 72,
    off_gcproto_chunkname: 64,
    off_gcstr_data: 24,
    off_gcfunc_cfunc: 40,
    off_gcfunc_ffid: 10,
    off_gcfunc_pc: 32,
    off_gcproto_bc: 104,
    off_gcstr_len: 20,
    off_l_glref: 16,
    off_global_state_dispatchmode: 146,
});

#[cfg(not(target_arch = "aarch64"))]
const LJ_OFFSETS_21: Option<LjOfs> = None;

// Feature flags for offsets should be the same across all architectures,
// but aarch64 flags are defined here to avoid unused issue.
#[cfg(target_arch = "aarch64")]
const LUA_FEAT_CI_ARRAY: u32 = 1 << 0;
#[cfg(target_arch = "aarch64")]
const LUA_FEAT_CI_LINKED: u32 = 1 << 1;
#[cfg(target_arch = "aarch64")]
const LUA_FEAT_LINEINFO: u32 = 1 << 2;
#[cfg(target_arch = "aarch64")]
const LUA_FEAT_PC_INSTR_INDEX: u32 = 1 << 3;
#[cfg(target_arch = "aarch64")]
const LUA_FEAT_CLOSURE_ISC: u32 = 1 << 4;
#[cfg(target_arch = "aarch64")]
const LUA_FEAT_LCF: u32 = 1 << 5;

#[derive(Hash, Eq, PartialEq, Copy, Clone)]
struct RuntimeKey {
    kind: u32,
    major: u8,
    minor: u8,
}

impl RuntimeKey {
    fn new(kind: u32, major: u8, minor: u8) -> Self {
        Self { kind, major, minor }
    }
}

#[derive(Default)]
pub struct LuaUnwindTable {
    lang_flags_fd: i32,
    unwind_info_fd: i32,
    lua_offsets_fd: i32,
    luajit_offsets_fd: i32,

    lua_offsets_ids: HashMap<RuntimeKey, u8>,
    luajit_offsets_ids: HashMap<RuntimeKey, u8>,
    lua_id_gen: IdGenerator,
    luajit_id_gen: IdGenerator,
}

impl LuaUnwindTable {
    pub unsafe fn new(
        lang_flags_fd: i32,
        unwind_info_fd: i32,
        lua_offsets_fd: i32,
        luajit_offsets_fd: i32,
    ) -> Self {
        Self {
            lang_flags_fd,
            unwind_info_fd,
            lua_offsets_fd,
            luajit_offsets_fd,
            ..Default::default()
        }
    }

    pub unsafe fn load(&mut self, pid: u32) {
        let info = match detect_runtime_cached(pid) {
            Some(info) => info,
            None => {
                debug!("no Lua runtime detected for process#{pid}");
                return;
            }
        };

        let version = info.version_str().trim();
        let path = info.path_str().trim();
        let label = info.detection_method_str().trim();
        info!(
            "Detect Lua for process#{pid}: kind={}, version=\"{}\", path=\"{}\", method=\"{}\"",
            info.kind, version, path, label
        );

        match info.kind {
            2 => self.handle_luajit(pid, version),
            1 => self.handle_lua(pid, version),
            _ => {}
        }
    }

    pub unsafe fn unload(&mut self, pid: u32) {
        trace!("unload lua unwind info for process#{pid}");
        let key = pid;
        if bpf_delete_elem(self.unwind_info_fd, &key as *const u32 as *const c_void) != 0 {
            let errno = get_errno();
            if errno != libc::ENOENT {
                warn!(
                    "delete lua unwind info for process#{pid} failed: bpf_delete_elem() returned {errno}"
                );
            }
        }

        if bpf_delete_elem(self.lang_flags_fd, &key as *const u32 as *const c_void) != 0 {
            let errno = get_errno();
            if errno != libc::ENOENT {
                warn!(
                    "delete lua lang flags for process#{pid} failed: bpf_delete_elem() returned {errno}"
                );
            }
        }

        // Avoid PID reuse issues by clearing any cached runtime detection and registration.
        crate::unregister_interpreter(pid);
        lua_layout_cache_remove(pid);
        runtime_cache_remove(pid);
    }

    unsafe fn handle_lua(&mut self, pid: u32, version: &str) {
        let (major, minor) = parse_version(version).unwrap_or((5, 0));
        let offsets = match (major, minor) {
            (5, 1) => LUA_51_OFFSETS,
            (5, 2) => LUA_52_OFFSETS,
            (5, 3) => LUA_53_OFFSETS,
            (5, 4) => LUA_54_OFFSETS,
            _ => None,
        };
        let offsets = match offsets {
            Some(o) => o,
            None => {
                debug!(
                    "unsupported Lua version {} for pid {} on this architecture",
                    version, pid
                );
                return;
            }
        };

        let key = RuntimeKey::new(1, major as u8, minor as u8);
        let mut inserted = false;
        let offsets_id = match self.lua_offsets_ids.get(&key) {
            Some(id) => *id,
            None => {
                let id = self.lua_id_gen.acquire() as u8;
                if self.update_offsets_map(self.lua_offsets_fd, id, &offsets) != 0 {
                    self.lua_id_gen.release(id as u32);
                    return;
                }
                self.lua_offsets_ids.insert(key, id);
                inserted = true;
                id
            }
        };

        if self.update_unwind_info(pid, offsets_id, 0).is_err() {
            if inserted {
                self.rollback_lua_offsets(key, offsets_id);
            }
            return;
        }

        if self.update_lang_flags(pid, LANG_LUA).is_err() {
            self.delete_unwind_info(pid);
            if inserted {
                self.rollback_lua_offsets(key, offsets_id);
            }
            return;
        }

        crate::register_interpreter(pid, crate::InterpreterType::Lua);
    }

    unsafe fn handle_luajit(&mut self, pid: u32, version: &str) {
        let (major, minor) = parse_version(version).unwrap_or((2, 1));
        if major != 2 {
            debug!("unsupported LuaJIT version {} for pid {}", version, pid);
            return;
        }

        let key = RuntimeKey::new(2, major as u8, minor as u8);
        let mut inserted = false;
        let offsets_id = match self.luajit_offsets_ids.get(&key) {
            Some(id) => *id,
            None => {
                let id = self.luajit_id_gen.acquire() as u8;
                let offsets = match LJ_OFFSETS_21 {
                    Some(o) => o,
                    None => {
                        debug!(
                            "unsupported LuaJIT architecture for pid {} (version {})",
                            pid, version
                        );
                        self.luajit_id_gen.release(id as u32);
                        return;
                    }
                };
                if self.update_luajit_offsets_map(self.luajit_offsets_fd, id, &offsets) != 0 {
                    self.luajit_id_gen.release(id as u32);
                    return;
                }
                self.luajit_offsets_ids.insert(key, id);
                inserted = true;
                id
            }
        };

        if self.update_unwind_info(pid, offsets_id, 0).is_err() {
            if inserted {
                self.rollback_luajit_offsets(key, offsets_id);
            }
            return;
        }

        if self.update_lang_flags(pid, LANG_LUAJIT).is_err() {
            self.delete_unwind_info(pid);
            if inserted {
                self.rollback_luajit_offsets(key, offsets_id);
            }
            return;
        }

        crate::register_interpreter(pid, crate::InterpreterType::Lua);
    }

    unsafe fn update_lang_flags(&self, pid: u32, mask: u32) -> Result<(), i32> {
        let key = pid;
        let ret = bpf_update_elem(
            self.lang_flags_fd,
            &key as *const u32 as *const c_void,
            &mask as *const u32 as *const c_void,
            BPF_ANY,
        );
        if ret != 0 {
            let errno = get_errno();
            warn!(
                "update lua lang flags for process#{pid} failed: bpf_update_elem() returned {errno}"
            );
            Err(errno)
        } else {
            trace!("lua lang flags updated for process#{pid}: mask=0x{mask:08x}");
            Ok(())
        }
    }

    unsafe fn update_unwind_info(
        &self,
        pid: u32,
        offsets_id: u8,
        state_addr: u64,
    ) -> Result<(), i32> {
        let key = pid;
        let info = LuaUnwindInfo {
            offsets_id,
            reserved: [0; 7],
            state_address: state_addr,
        };

        let value = slice::from_raw_parts(
            &info as *const LuaUnwindInfo as *const u8,
            mem::size_of::<LuaUnwindInfo>(),
        );

        let ret = bpf_update_elem(
            self.unwind_info_fd,
            &key as *const u32 as *const c_void,
            value.as_ptr() as *const c_void,
            BPF_ANY,
        );
        if ret != 0 {
            let errno = get_errno();
            warn!(
                "update lua unwind info for process#{pid} failed: bpf_update_elem() returned {errno}"
            );
            Err(errno)
        } else {
            trace!(
                "lua unwind info updated for process#{pid}: offsets_id={offsets_id}, state=0x{state_addr:016x}"
            );
            Ok(())
        }
    }

    unsafe fn delete_unwind_info(&self, pid: u32) {
        let key = pid;
        if bpf_delete_elem(self.unwind_info_fd, &key as *const u32 as *const c_void) != 0 {
            let errno = get_errno();
            if errno != libc::ENOENT {
                warn!(
                    "rollback lua unwind info for process#{pid} failed: bpf_delete_elem() returned {errno}"
                );
            }
        }
    }

    unsafe fn rollback_lua_offsets(&mut self, key: RuntimeKey, offsets_id: u8) {
        if self.lua_offsets_ids.remove(&key).is_some() {
            self.lua_id_gen.release(offsets_id as u32);
            let map_key = offsets_id as u32;
            if bpf_delete_elem(self.lua_offsets_fd, &map_key as *const u32 as *const c_void) != 0 {
                let errno = get_errno();
                if errno != libc::ENOENT {
                    warn!(
                        "rollback lua offsets (id={offsets_id}) failed: bpf_delete_elem() returned {errno}"
                    );
                }
            }
        }
    }

    unsafe fn rollback_luajit_offsets(&mut self, key: RuntimeKey, offsets_id: u8) {
        if self.luajit_offsets_ids.remove(&key).is_some() {
            self.luajit_id_gen.release(offsets_id as u32);
            let map_key = offsets_id as u32;
            if bpf_delete_elem(
                self.luajit_offsets_fd,
                &map_key as *const u32 as *const c_void,
            ) != 0
            {
                let errno = get_errno();
                if errno != libc::ENOENT {
                    warn!(
                        "rollback luajit offsets (id={offsets_id}) failed: bpf_delete_elem() returned {errno}"
                    );
                }
            }
        }
    }

    unsafe fn update_offsets_map(&self, fd: i32, id: u8, offsets: &LuaOfs) -> i32 {
        let key = id as u32;
        let value = slice::from_raw_parts(
            offsets as *const LuaOfs as *const u8,
            mem::size_of::<LuaOfs>(),
        );
        let ret = bpf_update_elem(
            fd,
            &key as *const u32 as *const c_void,
            value.as_ptr() as *const c_void,
            BPF_ANY,
        );
        if ret != 0 {
            let errno = get_errno();
            warn!(
                "update lua offsets map failed (key={}): bpf_update_elem() returned {errno}",
                key
            );
        }
        ret
    }

    unsafe fn update_luajit_offsets_map(&self, fd: i32, id: u8, offsets: &LjOfs) -> i32 {
        let key = id as u32;
        let value = slice::from_raw_parts(
            offsets as *const LjOfs as *const u8,
            mem::size_of::<LjOfs>(),
        );
        let ret = bpf_update_elem(
            fd,
            &key as *const u32 as *const c_void,
            value.as_ptr() as *const c_void,
            BPF_ANY,
        );
        if ret != 0 {
            let errno = get_errno();
            warn!(
                "update luajit offsets map failed (key={}): bpf_update_elem() returned {errno}",
                key
            );
        }
        ret
    }
}

#[no_mangle]
pub unsafe extern "C" fn lua_unwind_table_create(
    lang_flags_fd: i32,
    unwind_info_fd: i32,
    lua_offsets_fd: i32,
    luajit_offsets_fd: i32,
) -> *mut LuaUnwindTable {
    let table = Box::new(LuaUnwindTable::new(
        lang_flags_fd,
        unwind_info_fd,
        lua_offsets_fd,
        luajit_offsets_fd,
    ));
    Box::into_raw(table)
}

#[no_mangle]
pub unsafe extern "C" fn lua_unwind_table_destroy(table: *mut LuaUnwindTable) {
    if table.is_null() {
        return;
    }
    drop(Box::from_raw(table));
}

#[no_mangle]
pub unsafe extern "C" fn lua_unwind_table_load(table: *mut LuaUnwindTable, pid: u32) {
    if let Some(table) = table.as_mut() {
        table.load(pid);
    }
}

#[no_mangle]
pub unsafe extern "C" fn lua_unwind_table_unload(table: *mut LuaUnwindTable, pid: u32) {
    if let Some(table) = table.as_mut() {
        table.unload(pid);
    }
}

// --------- Runtime detection ---------

const LUA_NEGATIVE_DETECT_TTL: Duration = Duration::from_secs(30);
const LUA_DETECT_CACHE_MAX_ENTRIES: usize = 20_000;

#[derive(Clone, Copy)]
struct RuntimeCacheEntry {
    runtime: Option<LuaRuntimeInfo>,
    next_refresh_at: Option<Instant>,
}

static LUA_RUNTIME_CACHE: OnceLock<Mutex<HashMap<u32, RuntimeCacheEntry>>> = OnceLock::new();

fn runtime_cache() -> &'static Mutex<HashMap<u32, RuntimeCacheEntry>> {
    LUA_RUNTIME_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn runtime_cache_remove(pid: u32) {
    if let Ok(mut cache) = runtime_cache().lock() {
        cache.remove(&pid);
    }
}

fn detect_runtime_cached(pid: u32) -> Option<LuaRuntimeInfo> {
    let now = Instant::now();

    if let Ok(cache) = runtime_cache().lock() {
        if let Some(entry) = cache.get(&pid) {
            if let Some(info) = entry.runtime {
                return Some(info);
            }
            if let Some(next) = entry.next_refresh_at {
                if now < next {
                    return None;
                }
            }
        }
    }

    // Slow path: parse /proc/<pid>/maps (expensive). Do this outside the lock.
    let runtime = detect_runtime_uncached(pid);

    if let Ok(mut cache) = runtime_cache().lock() {
        if cache.len() >= LUA_DETECT_CACHE_MAX_ENTRIES {
            // Bound memory by dropping negative entries; positives are kept for lua_detect().
            cache.retain(|_, entry| entry.runtime.is_some());
        }
        cache.insert(
            pid,
            RuntimeCacheEntry {
                runtime,
                next_refresh_at: if runtime.is_some() {
                    None
                } else {
                    Some(now + LUA_NEGATIVE_DETECT_TTL)
                },
            },
        );
    }

    runtime
}

fn detect_runtime_uncached(pid: u32) -> Option<LuaRuntimeInfo> {
    let areas = get_memory_mappings(pid).ok()?;

    let mut best_prio: u8 = 0;
    let mut best_path = String::new();

    for area in &areas {
        let path = area.path.as_str();
        if path.is_empty() || path.starts_with('[') {
            continue;
        }
        let fname = path.rsplit('/').next().unwrap_or(path);
        let prio = if fname.starts_with("libluajit") {
            4
        } else if fname.starts_with("liblua") {
            3
        } else if fname.starts_with("luajit") {
            2
        } else if fname.starts_with("lua") {
            1
        } else {
            0
        };
        if prio > best_prio {
            best_prio = prio;
            best_path = path.to_owned();
            if prio == 4 {
                break;
            }
        }
    }

    if best_prio == 0 {
        return None;
    }

    let (kind, ver, label) = if best_path.contains("libluajit-5.1") || best_path.contains("luajit")
    {
        (2u32, "2.1", "LuaJIT 2.1")
    } else if best_path.contains("liblua5.4") || best_path.ends_with("/lua5.4") {
        (1u32, "5.4", "Pure Lua 5.4")
    } else if best_path.contains("liblua5.3") || best_path.ends_with("/lua5.3") {
        (1u32, "5.3", "Pure Lua 5.3")
    } else if best_path.contains("liblua5.2") || best_path.ends_with("/lua5.2") {
        (1u32, "5.2", "Pure Lua 5.2")
    } else if best_path.contains("liblua5.1")
        || best_path.ends_with("/lua5.1")
        || best_path.ends_with("/lua")
    {
        (1u32, "5.1", "Pure Lua 5.1")
    } else {
        (1u32, "", "Pure Lua (unknown)")
    };

    let mut info = LuaRuntimeInfo {
        kind,
        version: [0; LUA_RUNTIME_VERSION_LEN],
        detection_method: [0; LUA_RUNTIME_DETECT_METHOD_LEN],
        path: [0; LUA_RUNTIME_PATH_LEN],
    };

    let best_path_str = best_path.as_str();
    let full_path = if best_path_str.starts_with('/') {
        format!("/proc/{pid}/root{best_path_str}")
    } else {
        format!("/proc/{pid}/root/{best_path_str}")
    };

    let method = format!("Library analysis: {} ({})", full_path, label);
    copy_into(&mut info.version, ver.as_bytes());
    copy_into(&mut info.detection_method, method.as_bytes());
    copy_into(&mut info.path, full_path.as_bytes());

    Some(info)
}

fn parse_version(v: &str) -> Option<(u32, u32)> {
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some((major, minor))
}

fn copy_into<const N: usize>(dst: &mut [u8; N], src: &[u8]) {
    let max_copy = N.saturating_sub(1);
    let n = src.len().min(max_copy);
    if n > 0 {
        dst[..n].copy_from_slice(&src[..n]);
    }
    if n < N {
        dst[n] = 0;
    }
}

fn write_combined_output(dest: *mut c_void, len: usize, bytes: &[u8]) -> usize {
    if dest.is_null() || len == 0 {
        return 0;
    }

    unsafe {
        let ptr = dest as *mut u8;
        ptr.write_bytes(0, len);
        let copy_len = bytes.len().min(len);
        ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, copy_len);
        copy_len
    }
}
