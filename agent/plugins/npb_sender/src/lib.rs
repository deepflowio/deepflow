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

use std::fmt::Debug;
use std::io::{Error as IOError, ErrorKind, Result as IOResult};
use std::net::IpAddr;

#[derive(Debug)]
pub struct ZmqSender {
    pub dst_ip: IpAddr,
}

impl ZmqSender {
    pub fn new(dst_ip: &IpAddr, _: u16) -> Self {
        Self {
            dst_ip: dst_ip.clone(),
        }
    }

    pub fn send(&mut self, _: usize, _: Vec<u8>) -> IOResult<usize> {
        Err(IOError::new(ErrorKind::Other, "ZeroMQ not support."))
    }
}
