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

mod bit;
mod fast_path;
pub mod first_path;
mod forward;
pub mod labeler;
pub mod policy;

pub use policy::{Policy, PolicyGetter, PolicySetter};

use std::alloc::{dealloc, Layout};
use std::ptr;
use std::thread;
use std::time::Duration;

pub fn free(address: *mut u8, layout: Layout) {
    unsafe {
        thread::sleep(MEM_SAFE_TIME);
        ptr::drop_in_place(address);
        dealloc(address, layout);
    }
}

struct UnsafeWrapper<T> {
    pointer: *mut T,
}

const MEM_SAFE_TIME: Duration = Duration::from_millis(50);
const MAX_QUEUE_COUNT: usize = 128;

impl<T> From<T> for UnsafeWrapper<T> {
    fn from(value: T) -> Self {
        Self {
            pointer: Box::into_raw(Box::new(value)),
        }
    }
}

impl<T> UnsafeWrapper<T> {
    fn free(address: *mut u8, layout: Layout) {
        unsafe {
            thread::sleep(MEM_SAFE_TIME);
            ptr::drop_in_place(address);
            dealloc(address, layout);
        }
    }

    pub fn set(&mut self, p: T) {
        let p = Box::into_raw(Box::new(p));
        let last = self.pointer;
        self.pointer = p;
        Self::free(last as *mut u8, Layout::new::<T>());
    }

    pub fn get(&self) -> &T {
        return unsafe { &(*self.pointer) };
    }

    pub fn get_mut(&mut self) -> &mut T {
        return unsafe { &mut (*self.pointer) };
    }
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    CustomError(String),
    #[error(
        "DDBS memory limit will be exceed, please enlarge total memory limit or optimize policy."
    )]
    ExceedMemoryLimit,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
