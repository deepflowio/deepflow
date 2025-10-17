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

use std::{collections::HashMap, ffi::CStr, mem, slice};

use libc::{c_char, c_void, pid_t};
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

fn nul_terminated(bytes: &[u8]) -> &CStr {
    // Safety: cbindgen guarantees buffers are NUL-terminated when filled.
    unsafe { CStr::from_ptr(bytes.as_ptr() as *const c_char) }
}

#[inline]
fn runtime_version_bytes(info: &LuaRuntimeInfo) -> &CStr {
    nul_terminated(&info.version)
}

// --------- C FFI surface ---------

#[no_mangle]
pub extern "C" fn is_lua_process(pid: pid_t) -> i32 {
    if pid <= 0 {
        return 0;
    }
    detect_runtime(pid as u32).map(|_| 1).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn lua_detect(pid: pid_t, out: *mut LuaRuntimeInfo) -> i32 {
    if pid <= 0 || out.is_null() {
        return -1;
    }

    match detect_runtime(pid as u32) {
        Some(info) => {
            unsafe {
                *out = info;
            }
            0
        }
        None => -1,
    }
}

// --------- Lua unwind table plumbing ---------

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LuaUnwindInfo {
    pub offsets_id: u8,
    pub _reserved: [u8; 7],
    pub state_address: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(non_snake_case)]
struct LuaOfs {
    features: u32,
    off_L_ci: u32,
    off_L_base_ci: u32,
    off_L_end_ci: u32,
    off_CI_func: u32,
    off_CI_top: u32,
    off_CI_savedpc: u32,
    off_CI_prev: u32,
    off_TValue_tt: u32,
    off_TValue_val: u32,
    off_Closure_isC: u32,
    off_LClosure_p: u32,
    off_CClosure_f: u32,
    off_Proto_source: u32,
    off_Proto_linedefined: u32,
    off_Proto_code: u32,
    off_Proto_sizecode: u32,
    off_Proto_lineinfo: u32,
    off_Proto_abslineinfo: u32,
    off_TString_len: u32,
    sizeof_TString: u32,
    sizeof_CallInfo: u32,
    sizeof_TValue: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
#[allow(non_snake_case)]
struct LjOfs {
    fr2: u8,
    gc64: u8,
    _pad: u16,
    off_L_base: u32,
    off_L_stack: u32,
    off_GCproto_firstline: u32,
    off_GCproto_chunkname: u32,
    off_GCstr_data: u32,
    off_GCfunc_cfunc: u32,
    off_GCfunc_ffid: u32,
    off_GCfunc_pc: u32,
    off_GCproto_bc: u32,
    off_GCstr_len: u32,
    off_L_glref: u32,
    off_global_State_dispatchmode: u32,
}

#[allow(non_snake_case)]
const fn lua_ofs(
    features: u32,
    off_L_ci: u32,
    off_L_base_ci: u32,
    off_L_end_ci: u32,
    off_CI_func: u32,
    off_CI_top: u32,
    off_CI_savedpc: u32,
    off_CI_prev: u32,
    off_TValue_tt: u32,
    off_TValue_val: u32,
    off_Closure_isC: u32,
    off_LClosure_p: u32,
    off_CClosure_f: u32,
    off_Proto_source: u32,
    off_Proto_linedefined: u32,
    off_Proto_code: u32,
    off_Proto_sizecode: u32,
    off_Proto_lineinfo: u32,
    off_Proto_abslineinfo: u32,
    off_TString_len: u32,
    sizeof_TString: u32,
    sizeof_CallInfo: u32,
    sizeof_TValue: u32,
) -> LuaOfs {
    LuaOfs {
        features,
        off_L_ci,
        off_L_base_ci,
        off_L_end_ci,
        off_CI_func,
        off_CI_top,
        off_CI_savedpc,
        off_CI_prev,
        off_TValue_tt,
        off_TValue_val,
        off_Closure_isC,
        off_LClosure_p,
        off_CClosure_f,
        off_Proto_source,
        off_Proto_linedefined,
        off_Proto_code,
        off_Proto_sizecode,
        off_Proto_lineinfo,
        off_Proto_abslineinfo,
        off_TString_len,
        sizeof_TString,
        sizeof_CallInfo,
        sizeof_TValue,
    }
}

#[allow(non_snake_case)]
const fn lj_ofs(
    fr2: u8,
    gc64: u8,
    off_L_base: u32,
    off_L_stack: u32,
    off_GCproto_firstline: u32,
    off_GCproto_chunkname: u32,
    off_GCstr_data: u32,
    off_GCfunc_cfunc: u32,
    off_GCfunc_ffid: u32,
    off_GCfunc_pc: u32,
    off_GCproto_bc: u32,
    off_GCstr_len: u32,
    off_L_glref: u32,
    off_global_State_dispatchmode: u32,
) -> LjOfs {
    LjOfs {
        fr2,
        gc64,
        _pad: 0,
        off_L_base,
        off_L_stack,
        off_GCproto_firstline,
        off_GCproto_chunkname,
        off_GCstr_data,
        off_GCfunc_cfunc,
        off_GCfunc_ffid,
        off_GCfunc_pc,
        off_GCproto_bc,
        off_GCstr_len,
        off_L_glref,
        off_global_State_dispatchmode,
    }
}

const LUA_51_AARCH64: LuaOfs = lua_ofs(
    LUA_FEAT_CI_ARRAY | LUA_FEAT_LINEINFO | LUA_FEAT_PC_INSTR_INDEX | LUA_FEAT_CLOSURE_ISC,
    40,
    80,
    72,
    8,
    0,
    24,
    0,
    0,
    0,
    10,
    32,
    32,
    64,
    96,
    24,
    80,
    0,
    0,
    0,
    16,
    40,
    24,
);

const LUA_52_AARCH64: LuaOfs = lua_ofs(
    LUA_FEAT_CI_LINKED | LUA_FEAT_LINEINFO | LUA_FEAT_PC_INSTR_INDEX | LUA_FEAT_LCF,
    32,
    0,
    0,
    0,
    0,
    56,
    16,
    8,
    0,
    0,
    24,
    24,
    72,
    104,
    24,
    88,
    40,
    0,
    0,
    24,
    80,
    0,
);

const LUA_53_AARCH64: LuaOfs = lua_ofs(
    LUA_FEAT_CI_LINKED | LUA_FEAT_LINEINFO | LUA_FEAT_PC_INSTR_INDEX | LUA_FEAT_LCF,
    32,
    0,
    0,
    0,
    8,
    40,
    16,
    8,
    0,
    0,
    24,
    24,
    104,
    40,
    56,
    24,
    72,
    0,
    0,
    24,
    72,
    16,
);

const LUA_54_AARCH64: LuaOfs = lua_ofs(
    LUA_FEAT_CI_LINKED | LUA_FEAT_LINEINFO | LUA_FEAT_PC_INSTR_INDEX | LUA_FEAT_LCF,
    32,
    0,
    0,
    0,
    8,
    32,
    16,
    8,
    0,
    0,
    24,
    24,
    112,
    44,
    63,
    24,
    88,
    0,
    0,
    32,
    64,
    16,
);

const LJ_AARCH64_21_FR2_GC64: LjOfs =
    lj_ofs(1, 1, 32, 56, 72, 64, 24, 40, 10, 32, 104, 20, 16, 146);

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

        let version = runtime_version_bytes(&info)
            .to_str()
            .unwrap_or_default()
            .trim();
        let path = nul_terminated(&info.path)
            .to_str()
            .unwrap_or_default()
            .trim();
        let label = nul_terminated(&info.detection_method)
            .to_str()
            .unwrap_or_default()
            .trim();
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
            _reserved: [0; 7],
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
