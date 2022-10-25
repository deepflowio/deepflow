/*
 * Copyright (c) 2022 Yunshan Networks
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

use std::{mem::size_of, path::PathBuf, process};

use windows::Win32::{
    Foundation::{GetLastError, BOOL, CHAR, HINSTANCE, INVALID_HANDLE_VALUE, PWSTR},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
        },
        LibraryLoader::GetModuleFileNameW,
        ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

use log::debug;

use crate::{
    error::{Error, Result},
    utils::WIN_ERROR_CODE_STR,
};

//返回当前进程占用内存RSS单位（字节）
pub fn get_memory_rss() -> Result<u64> {
    let pid = process::id();
    let mut pmc = PROCESS_MEMORY_COUNTERS::default();

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, BOOL(0), pid);
        if handle == INVALID_HANDLE_VALUE {
            return Err(Error::Windows(format!(
                "get process handle failed pid={}",
                pid
            )));
        }

        if K32GetProcessMemoryInfo(
            handle,
            &mut pmc,
            size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
        .as_bool()
        {
            Ok(pmc.WorkingSetSize as u64)
        } else {
            Err(Error::Windows(format!(
                "run K32GetProcessMemoryInfo function failed pid={}",
                pid
            )))
        }
    }
}

// 仅计算当前进程及其子进程，没有计算子进程的子进程
pub fn get_process_num() -> Result<u32> {
    let pid = process::id();
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        let err_msg = format!(
            "failed to run get_process_num function because of win32 error code({}),\n{}",
            unsafe { GetLastError() },
            WIN_ERROR_CODE_STR
        );
        return Err(Error::Windows(err_msg));
    }

    let mut num = 0;
    loop {
        let mut entry = PROCESSENTRY32::default();
        entry.dwSize = size_of::<PROCESSENTRY32>() as u32;
        if let Err(e) = unsafe { Process32Next(snap, &mut entry).ok() } {
            debug!("failed to run Process32Next function error:{}", e);
            break;
        }

        if entry.th32ProcessID == pid || entry.th32ParentProcessID == pid {
            num += 1;
        }
    }
    Ok(num)
}

pub fn get_process_num_by_name(name: &str) -> Result<u32> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        let err_msg = format!(
            "failed to run get_process_num_by_name function because of win32 error code({}),\n{}",
            unsafe { GetLastError() },
            WIN_ERROR_CODE_STR
        );
        return Err(Error::Windows(err_msg));
    }

    let mut num = 0;
    loop {
        let mut entry = PROCESSENTRY32::default();
        entry.dwSize = size_of::<PROCESSENTRY32>() as u32;
        if let Err(e) = unsafe { Process32Next(snap, &mut entry).ok() } {
            debug!("failed to run Process32Next function error:{}", e);
            break;
        }

        if entry
            .szExeFile
            .iter()
            .position(|&x| x == CHAR(0)) // 找出 \0
            .and_then(|idx| entry.szExeFile.get(..idx))
            .filter(|&file| {
                file.into_iter()
                    .map(|c| c.0)
                    .collect::<Vec<u8>>()
                    .as_slice()
                    == name.as_bytes()
            })
            .is_some()
        {
            num += 1;
        }
    }
    Ok(num)
}

pub fn get_thread_num() -> Result<u32> {
    let pid = process::id();
    // 0 表示全部抓取
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        let err_msg = format!(
            "failed to run get_thread_num function because of win32 error code({}),\n{}",
            unsafe { GetLastError() },
            WIN_ERROR_CODE_STR
        );
        return Err(Error::Windows(err_msg));
    }

    let mut num = 0;
    loop {
        let mut entry = PROCESSENTRY32::default();
        entry.dwSize = size_of::<PROCESSENTRY32>() as u32;
        if let Err(e) = unsafe { Process32Next(snap, &mut entry).ok() } {
            debug!("failed to run Process32Next function error:{}", e);
            break;
        }

        if entry.th32ProcessID == pid || entry.th32ParentProcessID == pid {
            num += entry.cntThreads;
        }
    }
    Ok(num)
}

// returns the path name for the executable that started the current process
// reference: https://github.com/golang/go/blob/d2ce93960448559a7cb5685661502d8fc0c2ebc1/src/os/executable_windows.go#L12
// https://github.com/golang/go/blob/d2ce93960448559a7cb5685661502d8fc0c2ebc1/src/internal/syscall/windows/zsyscall_windows.go#L210
pub fn get_exec_path() -> Result<PathBuf> {
    let mut size = 128;
    let mut buf: Vec<u16> = vec![0u16; size];

    loop {
        let len = unsafe { GetModuleFileNameW(HINSTANCE(0), PWSTR(buf.as_mut_ptr()), size as u32) };
        if len == 0 {
            let err_msg = format!(
                "failed to run get_exec_path function because of win32 error code({}),\n{}",
                unsafe { GetLastError() },
                WIN_ERROR_CODE_STR
            );
            return Err(Error::Windows(err_msg));
        }

        if len < size as u32 {
            break;
        }
        // len == size means n not big enough
        size += 128;
        buf = Vec::with_capacity(size);
    }

    buf.iter()
        .position(|x| *x == 0)
        .and_then(|idx| buf.get(..idx))
        .and_then(|s| String::from_utf16(s).ok())
        .map(PathBuf::from)
        .ok_or(Error::Windows(String::from(
            "get_exec_path failed because current process exec_path is none",
        )))
}
