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

pub mod btf;
pub mod error;
pub mod maps;
pub mod unwind;
pub(crate) mod utils;

use std::io::Write;

use unwind::{python::PythonUnwindTable, UnwindTable};

#[no_mangle]
pub unsafe extern "C" fn unwind_table_create(
    process_shard_list_map_fd: i32,
    unwind_entry_shard_map_fd: i32,
) -> *mut UnwindTable {
    let table = Box::new(UnwindTable::new(
        process_shard_list_map_fd,
        unwind_entry_shard_map_fd,
    ));
    Box::into_raw(table)
}

#[no_mangle]
pub unsafe extern "C" fn unwind_table_destroy(table: *mut UnwindTable) {
    if table.is_null() {
        return;
    }
    std::mem::drop(Box::from_raw(table));
}

#[no_mangle]
pub unsafe extern "C" fn unwind_table_load(table: *mut UnwindTable, pid: u32) {
    (*table).load(pid);
}

#[no_mangle]
pub unsafe extern "C" fn unwind_table_unload(table: *mut UnwindTable, pid: u32) {
    (*table).unload(pid);
}

#[no_mangle]
pub unsafe extern "C" fn unwind_table_unload_all(table: *mut UnwindTable) {
    (*table).unload_all();
}

#[no_mangle]
pub unsafe extern "C" fn frame_pointer_heuristic_check(pid: u32) -> bool {
    unwind::dwarf::frame_pointer_heuristic_check(pid)
}

#[no_mangle]
pub unsafe extern "C" fn python_unwind_table_create(
    unwind_info_map_fd: i32,
    offsets_map_fd: i32,
) -> *mut PythonUnwindTable {
    let table = Box::new(PythonUnwindTable::new(unwind_info_map_fd, offsets_map_fd));
    Box::into_raw(table)
}

#[no_mangle]
pub unsafe extern "C" fn python_unwind_table_destroy(table: *mut PythonUnwindTable) {
    if !table.is_null() {
        std::mem::drop(Box::from_raw(table));
    }
}

#[no_mangle]
pub unsafe extern "C" fn python_unwind_table_load(table: *mut PythonUnwindTable, pid: u32) {
    (*table).load(pid);
}

#[no_mangle]
pub unsafe extern "C" fn python_unwind_table_unload(table: *mut PythonUnwindTable, pid: u32) {
    (*table).unload(pid);
}

// TODO: 暴露 lua 剖析相关函数给 C 部分

// forwards rust demangle to C api
// The code is from: https://github.com/rust-lang/rustc-demangle/blob/main/crates/capi/src/lib.rs
#[no_mangle]
pub unsafe extern "C" fn rustc_demangle(
    mangled: *const libc::c_char,
    out: *mut libc::c_char,
    out_size: usize,
) -> libc::c_int {
    let mangled_str = match std::ffi::CStr::from_ptr(mangled).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    match rustc_demangle::try_demangle(mangled_str) {
        Ok(demangle) => {
            let mut out_slice = std::slice::from_raw_parts_mut(out as *mut u8, out_size);
            match write!(out_slice, "{:#}\0", demangle) {
                Ok(_) => return 1,
                Err(_) => return 0,
            }
        }
        Err(_) => return 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn read_offset_of_stack_in_task_struct() -> i32 {
    match btf::read_offset_of_stack_in_task_struct() {
        Some(offset) => offset as i32,
        None => -1,
    }
}
