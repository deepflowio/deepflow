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
pub mod remote_memory;
pub mod unwind;
pub mod utils;
pub use utils::protect_cpu_affinity;

// Standard library
use std::io::Write;

// Third-party crates
use log::info;

// Crate internal modules
use unwind::UnwindTable;

// ============================================================================
// Global Registry (Generic)
// ============================================================================

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

// forwards rust demangle to C api
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

#[no_mangle]
pub unsafe extern "C" fn protect_cpu_affinity_c() -> i32 {
    match protect_cpu_affinity() {
        Ok(()) => 0, // Success -> return 0 to C
        Err(e) => {
            info!("protect_cpu_affinity_c failed: {e}");
            -1 // Failure -> return -1 to C
        }
    }
}

// ============================================================================
// Interpreter ABI (Enterprise)
// ============================================================================

#[cfg(feature = "enterprise")]
pub const LUA_RUNTIME_VERSION_LEN: usize = 32;
#[cfg(feature = "enterprise")]
pub const LUA_RUNTIME_DETECT_METHOD_LEN: usize = 256;
#[cfg(feature = "enterprise")]
pub const LUA_RUNTIME_PATH_LEN: usize = 1024;

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LuaRuntimeInfo {
    pub kind: u32,
    pub version: [u8; LUA_RUNTIME_VERSION_LEN],
    pub detection_method: [u8; LUA_RUNTIME_DETECT_METHOD_LEN],
    pub path: [u8; LUA_RUNTIME_PATH_LEN],
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PythonUnwindInfo {
    pub thread_state_address: u64,
    pub offsets_id: u8,
}

#[cfg(feature = "enterprise")]
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

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PyCframe {
    pub current_frame: i64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PyCodeObject {
    pub co_filename: i64,
    pub co_firstlineno: i64,
    pub co_name: i64,
    pub co_varnames: i64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PyFrameObject {
    pub f_back: i64,
    pub f_code: i64,
    pub f_lineno: i64,
    pub f_localsplus: i64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PyInterpreterFrame {
    pub owner: i64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PyInterpreterState {
    pub tstate_head: i64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PyObject {
    pub ob_type: i64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PyRuntimeState {
    pub interp_main: i64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PyString {
    pub data: i64,
    pub size: i64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PyThreadState {
    pub cframe: i64,
    pub frame: i64,
    pub interp: i64,
    pub native_thread_id: i64,
    pub next: i64,
    pub thread_id: i64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PyTupleObject {
    pub ob_item: i64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PyTypeObject {
    pub tp_name: i64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LuaUnwindInfo {
    pub offsets_id: u8,
    pub reserved: [u8; 7],
    pub state_address: u64,
}

#[cfg(feature = "enterprise")]
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

#[cfg(feature = "enterprise")]
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

#[cfg(feature = "enterprise")]
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

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PhpOffsets {
    pub executor_globals: PhpExecutorGlobals,
    pub execute_data: PhpExecuteData,
    pub function: PhpFunction,
    pub string: PhpString,
    pub op: PhpOp,
    pub class_entry: PhpClassEntry,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PhpExecutorGlobals {
    pub current_execute_data: u16,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PhpExecuteData {
    pub opline: u8,
    pub function: u8,
    pub this_type_info: u8,
    pub prev_execute_data: u8,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PhpFunction {
    pub common_type: u8,
    pub common_funcname: u8,
    pub common_scope: u8,
    pub op_array_filename: u32,
    pub op_array_linestart: u32,
    pub sizeof_struct: u32,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PhpString {
    pub val: u64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PhpOp {
    pub lineno: u8,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct PhpClassEntry {
    pub name: u64,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
pub struct V8UnwindInfo {
    pub isolate_address: u64,
    pub offsets_id: u8,
    pub version: u32,
}

#[cfg(feature = "enterprise")]
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

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8FramePointers {
    pub marker: i16,
    pub function: i16,
    pub bytecode_offset: i16,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8JSFunction {
    pub shared: u16,
    pub code: u16,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8SharedFunctionInfo {
    pub name_or_scope_info: u16,
    pub function_data: u16,
    pub script_or_debug_info: u16,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8Code {
    pub instruction_start: u16,
    pub instruction_size: u16,
    pub flags: u16,
    pub deoptimization_data: u16,
    pub source_position_table: u16,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8Script {
    pub name: u16,
    pub source: u16,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8BytecodeArray {
    pub source_position_table: u16,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8Type {
    pub scope_info: u16,
    pub shared_function_info: u16,
    pub js_function_first: u16,
    pub js_function_last: u16,
    pub string_first: u16,
    pub script: u16,
    pub code: u16,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8Fixed {
    pub first_nonstring_type: u16,
    pub string_representation_mask: u16,
    pub seq_string_tag: u16,
    pub cons_string_tag: u16,
    pub thin_string_tag: u16,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8ScopeInfoIndex {
    pub first_vars: u8,
    pub n_context_locals: u8,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8DeoptimizationDataIndex {
    pub inlined_function_count: u8,
    pub literal_array: u8,
    pub shared_function_info: u8,
    pub inlining_positions: u8,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8FrameTypes {
    pub entry_frame: u8,
    pub construct_entry_frame: u8,
    pub exit_frame: u8,
    pub wasm_frame: u8,
    pub wasm_to_js_frame: u8,
    pub wasm_to_js_function_frame: u8,
    pub js_to_wasm_frame: u8,
    pub wasm_debug_break_frame: u8,
    pub stack_switch_frame: u8,
    pub wasm_exit_frame: u8,
    pub c_wasm_entry_frame: u8,
    pub wasm_compile_lazy_frame: u8,
    pub wasm_liftoff_setup_frame: u8,
    pub interpreted_frame: u8,
    pub baseline_frame: u8,
    pub maglev_frame: u8,
    pub turbofan_frame: u8,
    pub stub_frame: u8,
    pub turbofan_stub_with_context_frame: u8,
    pub builtin_continuation_frame: u8,
    pub js_builtin_continuation_frame: u8,
    pub js_builtin_continuation_with_catch_frame: u8,
    pub internal_frame: u8,
    pub construct_frame: u8,
    pub fast_construct_frame: u8,
    pub builtin_frame: u8,
    pub builtin_exit_frame: u8,
    pub native_frame: u8,
    pub api_callback_exit_frame: u8,
    pub irregexp_frame: u8,
    pub optimized_frame: u8,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8HeapObject {
    pub map: u16,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8Map {
    pub instance_type: u16,
}

#[cfg(feature = "enterprise")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct V8CodeKind {
    pub mask: u32,
    pub shift: u8,
    pub baseline: u8,
    pub interpreted: u8,
}

// Opaque table handles (enterprise only).
#[cfg(feature = "enterprise")]
pub struct LuaUnwindTable;
#[cfg(feature = "enterprise")]
pub struct PythonUnwindTable;
#[cfg(feature = "enterprise")]
pub struct PhpUnwindTable;
#[cfg(feature = "enterprise")]
pub struct V8UnwindTable;

// Interpreter FFI declarations are provided by the enterprise crate.
#[cfg(feature = "enterprise")]
#[allow(improper_ctypes)]
extern "C" {
    pub fn is_lua_process(pid: u32) -> i32;
    pub fn is_python_process(pid: u32) -> bool;
    pub fn is_php_process(pid: u32) -> bool;
    pub fn is_v8_process(pid: u32) -> bool;

    pub fn lua_detect(pid: u32, out: *mut LuaRuntimeInfo) -> i32;
    pub fn lua_format_folded_stack_trace(
        tracer: *mut libc::c_void,
        pid: u32,
        frames: *const u64,
        frame_count: u32,
        new_cache: bool,
        info_p: *mut libc::c_void,
        err_tag: *const libc::c_char,
    ) -> *mut libc::c_char;
    pub fn lua_set_map_fds(
        lang_flags_fd: i32,
        unwind_info_fd: i32,
        lua_offsets_fd: i32,
        luajit_offsets_fd: i32,
    );

    pub fn lua_unwind_table_create(
        lang_flags_fd: i32,
        unwind_info_fd: i32,
        lua_offsets_fd: i32,
        luajit_offsets_fd: i32,
    ) -> *mut LuaUnwindTable;
    pub fn lua_unwind_table_destroy(table: *mut LuaUnwindTable);
    pub fn lua_unwind_table_load(table: *mut LuaUnwindTable, pid: u32);
    pub fn lua_unwind_table_unload(table: *mut LuaUnwindTable, pid: u32);

    pub fn python_unwind_table_create(
        unwind_info_map_fd: i32,
        offsets_map_fd: i32,
    ) -> *mut PythonUnwindTable;
    pub fn python_unwind_table_destroy(table: *mut PythonUnwindTable);
    pub fn python_unwind_table_load(table: *mut PythonUnwindTable, pid: u32);
    pub fn python_unwind_table_unload(table: *mut PythonUnwindTable, pid: u32);

    pub fn php_unwind_table_create(
        unwind_info_map_fd: i32,
        offsets_map_fd: i32,
    ) -> *mut PhpUnwindTable;
    pub fn php_unwind_table_destroy(table: *mut PhpUnwindTable);
    pub fn php_unwind_table_load(table: *mut PhpUnwindTable, pid: u32);
    pub fn php_unwind_table_unload(table: *mut PhpUnwindTable, pid: u32);

    pub fn v8_unwind_table_create(unwind_info_map_fd: i32) -> *mut V8UnwindTable;
    pub fn v8_unwind_table_destroy(table: *mut V8UnwindTable);
    pub fn v8_unwind_table_load(table: *mut V8UnwindTable, pid: u32);
    pub fn v8_unwind_table_unload(table: *mut V8UnwindTable, pid: u32);

    pub fn merge_lua_stacks(
        trace_str: *mut libc::c_void,
        len: usize,
        u_trace: *const libc::c_void,
        i_trace: *const libc::c_void,
    ) -> usize;
    pub fn merge_python_stacks(
        trace_str: *mut libc::c_void,
        len: usize,
        i_trace: *const libc::c_void,
        u_trace: *const libc::c_void,
    ) -> usize;
    pub fn merge_php_stacks(
        trace_str: *mut libc::c_void,
        len: usize,
        i_trace: *const libc::c_void,
        u_trace: *const libc::c_void,
    ) -> usize;
    pub fn merge_v8_stacks(
        trace_str: *mut libc::c_void,
        len: usize,
        i_trace: *const libc::c_void,
        u_trace: *const libc::c_void,
    ) -> usize;

    pub fn resolve_php_frame(
        pid: u32,
        zend_function_ptr: u64,
        lineno: u64,
        is_jit: u64,
    ) -> *mut libc::c_char;
    pub fn resolve_v8_frame(
        pid: u32,
        pointer_and_type: u64,
        delta_or_marker: u64,
        sfi_fallback: u64,
    ) -> *mut libc::c_char;
}
