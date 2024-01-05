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
 * distributed under the License is distributed on an "AS IS" BASIS：w,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use super::{flow_node::FlowNode, perf::tcp::TcpPerf};

pub trait Recyclable {
    fn reset(&mut self);
}

impl Recyclable for FlowNode {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl Recyclable for TcpPerf {
    fn reset(&mut self) {
        TcpPerf::reset(self);
    }
}

pub struct MemoryPool<T: Recyclable> {
    size: usize,
    objs: Vec<Box<T>>,
}

impl<T: Recyclable> MemoryPool<T> {
    pub fn new(size: usize) -> Self {
        Self {
            size,
            objs: Vec::with_capacity(size),
        }
    }

    pub fn get(&mut self) -> Option<Box<T>> {
        self.objs.pop()
    }

    pub fn put(&mut self, mut obj: Box<T>) {
        if self.objs.len() >= self.size {
            return;
        }

        obj.reset();
        self.objs.push(obj);
    }
}
