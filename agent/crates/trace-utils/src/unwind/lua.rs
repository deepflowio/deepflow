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

use std::{collections::HashMap, ffi::CStr, mem, ptr, slice, str};

use libc::{c_char, c_void};
use log::{debug, info, trace, warn};

use crate::maps::get_memory_mappings;
use crate::utils::{bpf_delete_elem, bpf_update_elem, get_errno, IdGenerator, BPF_ANY};

const LANG_LUA: u32 = 1 << 0;
const LANG_LUAJIT: u32 = 1 << 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LuaRuntimeInfo {
    pub kind: u32,         // 0 = none, 1 = Lua, 2 = LuaJIT
    pub version: [u8; 32], // e.g. "5.4", "5.3", "2.1"
    pub detection_method: [u8; 256],
    pub path: [u8; 512],
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
    detect_runtime(pid as u32).is_some() as i32
}

#[no_mangle]
pub unsafe extern "C" fn lua_detect(pid: u32, out: *mut LuaRuntimeInfo) -> i32 {
    if pid <= 0 || out.is_null() {
        return -1;
    }

    match detect_runtime(pid as u32) {
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

    if !should_merge_lua_into_stack(user, lua) {
        return write_combined_output(trace_str, len, user.as_bytes());
    }

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

    for frame in user.split(';').filter(|s| !s.is_empty()) {
        let should_replace =
            frame.starts_with("[unknown") || frame.starts_with("[unkown");
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

fn should_merge_lua_into_stack(user: &str, lua: &str) -> bool {
    if lua.is_empty() {
        return false;
    }

    // must contain a known Lua interpreter symbol
    const LUA_INTERP_HINTS: &[&str] = &[
        "lua_resume",
        "luaV_",
        "luaD_",
        "luaB_",
        "lua_yield",
        "luaF_",
        "liblua",
    ];
    if !LUA_INTERP_HINTS.iter().any(|hint| user.contains(hint)) {
        return false;
    }

    // reject when top frame looks like idle/wait/sleep functions
    const REJECT_KEYWORDS: &[&str] = &[
        "sleep",
        "nanosleep",
        "poll",
        "epoll",
        "select",
        "usleep",
        "clock_nanosleep",
        "futex",
        "pthread",
        "ld-linux",
        "libc.so",
        "libpthread.so",
    ];

    // extract top user-space frame (before first kernel frame)
    let mut top_user_frame: Option<&str> = None;
    for frame in user.split(';') {
        if frame.is_empty() {
            continue;
        }
        if frame.starts_with("[k]") {
            break;
        }
        top_user_frame = Some(frame);
    }

    if let Some(frame) = top_user_frame {
        let frame_lower = frame.to_ascii_lowercase();
        if REJECT_KEYWORDS.iter().any(|kw| frame_lower.contains(kw)) {
            return false;
        }
    }

    true
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
struct LuaOfs {
    features: u32,
    off_l_ci: u32,
    off_l_base_ci: u32,
    off_l_end_ci: u32,
    off_ci_func: u32,
    off_ci_top: u32,
    off_ci_savedpc: u32,
    off_ci_prev: u32,
    off_tvalue_tt: u32,
    off_tvalue_val: u32,
    off_closure_isc: u32,
    off_lclosure_p: u32,
    off_cclosure_f: u32,
    off_proto_source: u32,
    off_proto_linedefined: u32,
    off_proto_code: u32,
    off_proto_sizecode: u32,
    off_proto_lineinfo: u32,
    off_proto_abslineinfo: u32,
    off_tstring_len: u32,
    sizeof_tstring: u32,
    sizeof_callinfo: u32,
    sizeof_tvalue: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct LjOfs {
    fr2: u8,
    gc64: u8,
    pad: u16,
    off_l_base: u32,
    off_l_stack: u32,
    off_gcproto_firstline: u32,
    off_gcproto_chunkname: u32,
    off_gcstr_data: u32,
    off_gcfunc_cfunc: u32,
    off_gcfunc_ffid: u32,
    off_gcfunc_pc: u32,
    off_gcproto_bc: u32,
    off_gcstr_len: u32,
    off_l_glref: u32,
    off_global_state_dispatchmode: u32,
}

const LUA_51_AARCH64: LuaOfs = LuaOfs {
    features: LUA_FEAT_CI_ARRAY | LUA_FEAT_LINEINFO | LUA_FEAT_PC_INSTR_INDEX | LUA_FEAT_CLOSURE_ISC,
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
};

const LUA_52_AARCH64: LuaOfs = LuaOfs {
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
};

const LUA_53_AARCH64: LuaOfs = LuaOfs {
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
};

const LUA_54_AARCH64: LuaOfs = LuaOfs {
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
};

const LJ_AARCH64_21_FR2_GC64: LjOfs = LjOfs {
    fr2: 1,
    gc64: 1,
    pad: 0,
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
};

const LUA_FEAT_CI_ARRAY: u32 = 1 << 0;
const LUA_FEAT_CI_LINKED: u32 = 1 << 1;
const LUA_FEAT_LINEINFO: u32 = 1 << 2;
const LUA_FEAT_PC_INSTR_INDEX: u32 = 1 << 3;
const LUA_FEAT_CLOSURE_ISC: u32 = 1 << 4;
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
        trace!("load lua unwind info for process#{pid}");
        let info = match detect_runtime(pid) {
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
            "detected Lua runtime for process#{pid}: kind={}, version=\"{}\", path=\"{}\", method=\"{}\"",
            info.kind,
            version,
            path,
            label
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
    }

    unsafe fn handle_lua(&mut self, pid: u32, version: &str) {
        let (major, minor) = parse_version(version).unwrap_or((5, 0));
        let offsets = match (major, minor) {
            (5, 1) => LUA_51_AARCH64,
            (5, 2) => LUA_52_AARCH64,
            (5, 3) => LUA_53_AARCH64,
            (5, 4) => LUA_54_AARCH64,
            _ => {
                debug!("unsupported Lua version {} for pid {}", version, pid);
                return;
            }
        };

        let key = RuntimeKey::new(1, major as u8, minor as u8);
        let offsets_id = match self.lua_offsets_ids.get(&key) {
            Some(id) => *id,
            None => {
                let id = self.lua_id_gen.acquire() as u8;
                if self.update_offsets_map(self.lua_offsets_fd, id, &offsets) != 0 {
                    self.lua_id_gen.release(id as u32);
                    return;
                }
                self.lua_offsets_ids.insert(key, id);
                id
            }
        };

        self.update_unwind_info(pid, offsets_id, 0);
        self.update_lang_flags(pid, LANG_LUA);
    }

    unsafe fn handle_luajit(&mut self, pid: u32, version: &str) {
        let (major, minor) = parse_version(version).unwrap_or((2, 1));
        if major != 2 {
            debug!("unsupported LuaJIT version {} for pid {}", version, pid);
            return;
        }

        let key = RuntimeKey::new(2, major as u8, minor as u8);
        let offsets_id = match self.luajit_offsets_ids.get(&key) {
            Some(id) => *id,
            None => {
                let id = self.luajit_id_gen.acquire() as u8;
                if self.update_luajit_offsets_map(
                    self.luajit_offsets_fd,
                    id,
                    &LJ_AARCH64_21_FR2_GC64,
                ) != 0
                {
                    self.luajit_id_gen.release(id as u32);
                    return;
                }
                self.luajit_offsets_ids.insert(key, id);
                id
            }
        };

        self.update_unwind_info(pid, offsets_id, 0);
        self.update_lang_flags(pid, LANG_LUAJIT);
    }

    unsafe fn update_lang_flags(&self, pid: u32, mask: u32) {
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
        } else {
            info!("lua lang flags updated for process#{pid}: mask=0x{mask:08x}");
        }
    }

    unsafe fn update_unwind_info(&self, pid: u32, offsets_id: u8, state_addr: u64) {
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
        } else {
            info!(
                "lua unwind info updated for process#{pid}: offsets_id={offsets_id}, state=0x{state_addr:016x}"
            );
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

fn detect_runtime(pid: u32) -> Option<LuaRuntimeInfo> {
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
        version: [0; 32],
        detection_method: [0; 256],
        path: [0; 512],
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
