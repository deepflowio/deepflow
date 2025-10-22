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

//! Remote memory reading utilities for reading process memory.
//!
//! This module provides efficient remote memory reading capabilities using
//! process_vm_readv system call on Linux, which allows reading memory from
//! another process without needing to open /proc/pid/mem files.

use std::io;
use std::mem;

use libc::{c_void, iovec, pid_t, process_vm_readv};

use crate::error::Result;

/// A reader for remote process memory using process_vm_readv.
///
/// This provides efficient zero-copy memory reading from remote processes,
/// which is essential for V8/Node.js symbolization where we need to read
/// JavaScript heap objects from the target process.
pub struct RemoteMemory {
    pid: pid_t,
}

impl RemoteMemory {
    /// Create a new remote memory reader for the given process ID.
    pub fn new(pid: u32) -> Self {
        Self { pid: pid as pid_t }
    }

    /// Read memory from the remote process at the given address.
    ///
    /// # Arguments
    /// * `address` - Remote memory address to read from
    /// * `buffer` - Local buffer to read data into
    ///
    /// # Returns
    /// Number of bytes actually read, or an error.
    pub fn read_at(&self, address: u64, buffer: &mut [u8]) -> Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let local_iov = iovec {
            iov_base: buffer.as_mut_ptr() as *mut c_void,
            iov_len: buffer.len(),
        };

        let remote_iov = iovec {
            iov_base: address as *mut c_void,
            iov_len: buffer.len(),
        };

        let bytes_read = unsafe {
            process_vm_readv(
                self.pid,
                &local_iov as *const iovec,
                1, // local iov count
                &remote_iov as *const iovec,
                1, // remote iov count
                0, // flags
            )
        };

        if bytes_read < 0 {
            return Err(io::Error::last_os_error().into());
        }

        if bytes_read as usize != buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "Short read from PID {} at 0x{:x}: got {} of {} bytes",
                    self.pid,
                    address,
                    bytes_read,
                    buffer.len()
                ),
            )
            .into());
        }

        Ok(bytes_read as usize)
    }

    /// Read a value of type T from the remote process.
    ///
    /// # Safety
    /// The caller must ensure that:
    /// - The address is valid and aligned for type T
    /// - Reading sizeof(T) bytes from address is safe
    /// - The memory layout of T is compatible between processes
    pub unsafe fn read_value<T>(&self, address: u64) -> Result<T>
    where
        T: Copy,
    {
        let mut value: T = mem::zeroed();
        let buffer =
            std::slice::from_raw_parts_mut(&mut value as *mut T as *mut u8, mem::size_of::<T>());
        self.read_at(address, buffer)?;
        Ok(value)
    }

    /// Read a u64 value from the remote process.
    pub fn read_u64(&self, address: u64) -> Result<u64> {
        unsafe { self.read_value::<u64>(address) }
    }

    /// Read a u32 value from the remote process.
    pub fn read_u32(&self, address: u64) -> Result<u32> {
        unsafe { self.read_value::<u32>(address) }
    }

    /// Read a u16 value from the remote process.
    pub fn read_u16(&self, address: u64) -> Result<u16> {
        unsafe { self.read_value::<u16>(address) }
    }

    /// Read a u8 value from the remote process.
    pub fn read_u8(&self, address: u64) -> Result<u8> {
        unsafe { self.read_value::<u8>(address) }
    }

    /// Read a pointer (usize) from the remote process.
    pub fn read_ptr(&self, address: u64) -> Result<u64> {
        self.read_u64(address)
    }

    /// Read a null-terminated string from the remote process.
    ///
    /// # Arguments
    /// * `address` - Address of the string in remote process
    /// * `max_len` - Maximum length to read (prevents infinite loops)
    ///
    /// # Returns
    /// The string read, up to the first null byte or max_len.
    pub fn read_cstring(&self, address: u64, max_len: usize) -> Result<String> {
        let mut buffer = vec![0u8; max_len];

        match self.read_at(address, &mut buffer) {
            Ok(_) => {
                // Find the first null byte
                if let Some(null_pos) = buffer.iter().position(|&b| b == 0) {
                    buffer.truncate(null_pos);
                }

                // Convert to UTF-8, replacing invalid sequences
                Ok(String::from_utf8_lossy(&buffer).into_owned())
            }
            Err(e) => Err(e),
        }
    }

    /// Read multiple scattered memory regions in a single system call.
    ///
    /// This is more efficient than multiple read_at calls when reading
    /// multiple non-contiguous memory regions.
    ///
    /// # Arguments
    /// * `reads` - Vec of (remote_address, local_buffer) pairs
    ///
    /// # Returns
    /// Total number of bytes read, or an error.
    pub fn read_scatter(&self, reads: &mut [(u64, &mut [u8])]) -> Result<usize> {
        if reads.is_empty() {
            return Ok(0);
        }

        let mut local_iovs: Vec<iovec> = Vec::with_capacity(reads.len());
        let mut remote_iovs: Vec<iovec> = Vec::with_capacity(reads.len());

        for (addr, buf) in reads.iter_mut() {
            local_iovs.push(iovec {
                iov_base: buf.as_mut_ptr() as *mut c_void,
                iov_len: buf.len(),
            });
            remote_iovs.push(iovec {
                iov_base: *addr as *mut c_void,
                iov_len: buf.len(),
            });
        }

        let bytes_read = unsafe {
            process_vm_readv(
                self.pid,
                local_iovs.as_ptr(),
                local_iovs.len() as u64,
                remote_iovs.as_ptr(),
                remote_iovs.len() as u64,
                0,
            )
        };

        if bytes_read < 0 {
            return Err(io::Error::last_os_error().into());
        }

        Ok(bytes_read as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_self_memory() {
        let test_value: u64 = 0xDEADBEEFCAFEBABE;
        let address = &test_value as *const u64 as u64;

        let remote_mem = RemoteMemory::new(std::process::id());
        let read_value = remote_mem.read_u64(address).expect("Failed to read");

        assert_eq!(read_value, test_value);
    }

    #[test]
    fn test_read_cstring() {
        let test_str = b"Hello, World!\0Extra data";
        let address = test_str.as_ptr() as u64;

        let remote_mem = RemoteMemory::new(std::process::id());
        let read_str = remote_mem
            .read_cstring(address, 256)
            .expect("Failed to read string");

        assert_eq!(read_str, "Hello, World!");
    }
}
