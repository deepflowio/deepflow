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

use std::{ffi::OsString, io, os::windows::ffi::OsStringExt, path::PathBuf, ptr};

use bytesize::ByteSize;
use sysinfo::{System, SystemExt};
use winapi::{
    shared::minwindef::{DWORD, MAX_PATH},
    um::libloaderapi::GetModuleFileNameW,
};

use crate::{
    error::{Error, Result},
    exception::ExceptionHandler,
    utils::process::get_memory_rss,
};
use public::proto::trident::Exception;

pub fn free_memory_check(required: u64, exception_handler: &ExceptionHandler) -> Result<()> {
    get_memory_rss()
        .map_err(|e| Error::Environment(e.to_string()))
        .and_then(|memory_usage| {
            if required < memory_usage {
                return Ok(());
            }

            let still_need = required - memory_usage;
            let mut system = System::new();
            system.refresh_memory();

            if still_need <= system.available_memory() {
                exception_handler.clear(Exception::MemNotEnough);
                Ok(())
            } else {
                exception_handler.set(Exception::MemNotEnough);
                Err(Error::Environment(format!(
                    "need {} more memory to run",
                    ByteSize::b(still_need).to_string_as(true)
                )))
            }
        })
}

pub fn kernel_check() {}

pub fn tap_interface_check(_tap_interfaces: &[String]) {}

pub fn get_executable_path() -> Result<PathBuf, io::Error> {
    let mut buf = Vec::with_capacity(MAX_PATH);
    unsafe {
        let ret = GetModuleFileNameW(ptr::null_mut(), buf.as_mut_ptr(), MAX_PATH as DWORD) as usize;
        if ret > 0 && ret < MAX_PATH {
            buf.set_len(ret);
            let s = OsString::from_wide(&buf);
            Ok(s.into())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "executable path not found",
            ))
        }
    }
}
