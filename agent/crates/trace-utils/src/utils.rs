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

use std::collections::VecDeque;

use libc::{c_int, c_longlong, c_void};

#[derive(Default)]
pub struct IdGenerator {
    max_id: u32,
    available: VecDeque<u32>,
}

impl IdGenerator {
    pub fn acquire(&mut self) -> u32 {
        if let Some(id) = self.available.pop_front() {
            return id;
        }
        self.max_id += 1;
        self.max_id - 1
    }

    pub fn release(&mut self, id: u32) {
        self.available.push_back(id);
    }
}

pub const BPF_ANY: c_longlong = 0;
extern "C" {
    pub fn bpf_update_elem(
        fd: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: c_longlong,
    ) -> c_int;
    pub fn bpf_delete_elem(fd: c_int, key: *const c_void) -> c_int;
}

pub(crate) unsafe fn get_errno() -> i32 {
    cfg_if::cfg_if! {
        if #[cfg(any(target_os = "linux", target_os = "android"))] {
            *libc::__errno_location()
        } else {
            unimplemented!()
        }
    }
}
