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

use std::ffi::CString;
use std::net::{SocketAddr, UdpSocket};
use std::slice;
use std::time::{Duration, Instant};

use bincode::config::Configuration;
use bincode::{Decode, Encode};
use libc::{c_char, c_int};
use log::warn;

use crate::ebpf::{cpdbg_set_config, datadump_set_config};
use public::{
    debug::send_to,
    queue::{bounded, Receiver, Sender},
};

#[derive(PartialEq, Debug, Encode, Decode)]
pub enum EbpfMessage {
    DataDump((u32, String, u8, u16)),
    Cpdbg(u16),
    Context(Vec<u8>),
    Error(String),
    Done,
}

pub struct EbpfDebugger {
    receiver: Receiver<Vec<u8>>,
}

static mut EBPF_DEBUG_SENDER: Option<Sender<Vec<u8>>> = None;

impl EbpfDebugger {
    const QUEUE_RECV_TIMEOUT: Duration = Duration::from_secs(1);

    extern "C" fn ebpf_debug(data: *mut c_char, len: c_int) {
        unsafe {
            if let Some(ebpf_debug_sender) = &EBPF_DEBUG_SENDER {
                let datas = slice::from_raw_parts(data as *mut u8, len as usize).to_vec();
                let _ = ebpf_debug_sender.send(datas);
            }
        }
    }

    pub fn new() -> Self {
        let (sender, receiver, _) = bounded(1024);
        unsafe {
            EBPF_DEBUG_SENDER = Some(sender);
        }
        Self { receiver }
    }

    pub fn cpdbg(
        &self,
        sock: &UdpSocket,
        conn: SocketAddr,
        serialize_conf: Configuration,
        msg: &EbpfMessage,
    ) {
        let EbpfMessage::Cpdbg(timeout) = msg else {
            return;
        };
        let now = Instant::now();
        let duration = Duration::from_secs(*timeout as u64);
        unsafe {
            cpdbg_set_config(*timeout as c_int, Self::ebpf_debug);
        }
        while now.elapsed() < duration {
            let s = match self.receiver.recv(Some(Self::QUEUE_RECV_TIMEOUT)) {
                Ok(s) => s,
                _ => continue,
            };

            if let Err(e) = send_to(&sock, conn, EbpfMessage::Context(s), serialize_conf) {
                warn!("send ebpf item error: {}", e);
            }
        }
        if let Err(e) = send_to(&sock, conn, EbpfMessage::Done, serialize_conf) {
            warn!("send ebpf item error: {}", e);
        }
    }

    pub fn datadump(
        &self,
        sock: &UdpSocket,
        conn: SocketAddr,
        serialize_conf: Configuration,
        msg: &EbpfMessage,
    ) {
        let EbpfMessage::DataDump((pid, name, protocol, timeout)) = msg else {
            return;
        };
        let now = Instant::now();
        let duration = Duration::from_secs(*timeout as u64);
        unsafe {
            datadump_set_config(
                *pid as i32,
                CString::new(name.as_bytes()).unwrap().as_c_str().as_ptr(),
                *protocol as i32,
                *timeout as c_int,
                Self::ebpf_debug,
            );
        }
        while now.elapsed() < duration {
            let s = match self.receiver.recv(Some(Self::QUEUE_RECV_TIMEOUT)) {
                Ok(s) => s,
                _ => continue,
            };

            if let Err(e) = send_to(&sock, conn, EbpfMessage::Context(s), serialize_conf) {
                warn!("send ebpf item error: {}", e);
            }
        }
        if let Err(e) = send_to(&sock, conn, EbpfMessage::Done, serialize_conf) {
            warn!("send ebpf item error: {}", e);
        }
    }
}
