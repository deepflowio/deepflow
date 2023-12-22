/*
 * Copyright (c) 2023 Yunshan Networks
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

#[cfg(test)]
mod test;

use std::ffi::CStr;
use std::ffi::CString;
use std::sync::atomic::AtomicU64;

use libc::c_void;
use md5::{Digest, Md5};
use public::counter::{CounterType, CounterValue, RefCountable};

use super::c_ffi::SoPluginFunc;
use super::c_ffi::{CHECK_PAYLOAD_FUNC_SYM, INIT_FUNC_SYM, PARSE_PAYLOAD_FUNC_SYM};

pub fn load_plugin(plugin: &[u8], name: &String) -> Result<SoPluginFunc, String> {
    let file_name = CString::new(name.as_bytes()).unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, file_name.as_ptr(), 0) as i32 };
    if fd < 0 {
        return Err("tmp file create fail".to_string());
    }

    /*
        get the function from so sym,  correctness depends on plugin implementation

        there is impossible to verify the function signature correctness, export the function sym with wrong param and return type is UB
    */
    let (check_func, parse_func) = unsafe {
        if libc::write(fd, plugin.as_ptr() as *const c_void, plugin.len()) != plugin.len() as isize
        {
            libc::close(fd);
            return Err("write plugin to tmp file fail".to_string());
        };
        let fd_path = CString::new(format!("/dev/fd/{}", fd)).unwrap();
        let handle = libc::dlopen(fd_path.as_ptr(), libc::RTLD_LOCAL | libc::RTLD_LAZY);
        if handle.is_null() {
            libc::close(fd);
            return Err(CStr::from_ptr(libc::dlerror())
                .to_str()
                .unwrap()
                .to_string());
        }

        let get_func = |sym: &str| {
            let func_sym = CString::new(sym).unwrap();
            let func = libc::dlsym(handle, func_sym.as_ptr());
            if func.is_null() {
                libc::close(fd);
                Err(CStr::from_ptr(libc::dlerror())
                    .to_str()
                    .unwrap()
                    .to_string())
            } else {
                Ok(func)
            }
        };

        let (init_func, check_func, parse_func) = (
            get_func(INIT_FUNC_SYM)?,
            get_func(CHECK_PAYLOAD_FUNC_SYM)?,
            get_func(PARSE_PAYLOAD_FUNC_SYM)?,
        );
        libc::close(fd);
        let init: extern "C" fn() = std::mem::transmute(init_func);
        init();

        (
            std::mem::transmute(check_func),
            std::mem::transmute(parse_func),
        )
    };
    Ok(SoPluginFunc {
        hash: Md5::digest(plugin)
            .into_iter()
            .fold(String::new(), |s, c| s + &format!("{:02x}", c)),
        name: name.clone(),
        check_payload_counter: Default::default(),
        parse_payload_counter: Default::default(),
        check_payload: check_func,
        parse_payload: parse_func,
    })
}

#[derive(Debug, Default)]
pub struct SoPluginCounter {
    pub exe_duration: AtomicU64,
    pub fail_cnt: AtomicU64,
}

impl RefCountable for SoPluginCounter {
    fn get_counters(&self) -> Vec<public::counter::Counter> {
        vec![
            (
                "execute_duration",
                CounterType::Gauged,
                CounterValue::Unsigned(
                    self.exe_duration
                        .swap(0, std::sync::atomic::Ordering::Relaxed),
                ),
            ),
            (
                "fail_cnt",
                CounterType::Counted,
                CounterValue::Unsigned(self.fail_cnt.swap(0, std::sync::atomic::Ordering::Relaxed)),
            ),
        ]
    }
}

pub const SO_EXPORT_FUNC_NAME: [&'static str; 2] = [CHECK_PAYLOAD_FUNC_SYM, PARSE_PAYLOAD_FUNC_SYM];
