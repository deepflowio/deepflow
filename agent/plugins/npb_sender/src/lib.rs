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
use std::thread;
use std::time::{Duration, SystemTime};

use log::info;
use nom::AsBytes;
use zmq;

use npb_handler::NpbHeader;
use public::consts::{TCP6_PACKET_SIZE, TCP_PACKET_SIZE};

pub struct ZmqSender {
    socket: Option<zmq::Socket>,
    underlay_is_ipv6: bool,

    overlay_packet_offset: usize,

    pub dst_ip: IpAddr,
    dst_port: u16,

    last_connect: u32, // time in second
}

impl Debug for ZmqSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "socket: {} underlay_is_ipv6: {} overlay_packet_offset: {} dst_ip: {} dst_port: {} last_connect: {}",
             self.socket.is_some(), self.underlay_is_ipv6, self.overlay_packet_offset, self.dst_ip, self.dst_port, self.last_connect
         )
    }
}

impl ZmqSender {
    const CONNECT_INTERVAL: u32 = 10; // time in second
    const MAX_TRY_COUNT: usize = 3000;

    pub fn new(dst_ip: &IpAddr, dst_port: u16) -> Self {
        Self {
            socket: None,
            underlay_is_ipv6: dst_ip.is_ipv6(),
            overlay_packet_offset: if dst_ip.is_ipv6() {
                TCP6_PACKET_SIZE
            } else {
                TCP_PACKET_SIZE
            },
            dst_port,
            dst_ip: dst_ip.clone(),
            last_connect: 0,
        }
    }

    pub fn connect(&mut self) -> IOResult<()> {
        let ctx = zmq::Context::new();
        let socket = ctx.socket(zmq::REQ).unwrap();
        let remote = format!("tcp://{}:{}", self.dst_ip, self.dst_port);

        socket.connect(&remote).map_err(|e| {
            IOError::new(
                ErrorKind::Other,
                format!("ZeroMQ init with {} failed: {:?}", remote, e),
            )
        })?;

        self.socket.replace(socket);
        info!("Npb ZeroMQ init with {}.", remote);
        Ok(())
    }

    pub fn connect_check(&mut self) -> IOResult<()> {
        if self.socket.is_some() {
            return Ok(());
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        // If the local timestamp adjustment requires recalculating the interval
        if self.last_connect > now {
            self.last_connect = now;
        }
        if self.last_connect + Self::CONNECT_INTERVAL > now {
            return Err(IOError::new(
                ErrorKind::Other,
                "Waiting for reconnection time interval",
            ));
        }
        self.last_connect = now;
        self.connect()
    }

    pub fn send_timeout(socket: &zmq::Socket, packet: &[u8], timeout: usize) -> IOResult<usize> {
        let mut error = String::new();
        for _ in 0..timeout {
            let Err(e) = socket.send(packet, 1) else {
                return Ok(packet.len());
            };
            error = format!("ZeroMQ send failed: {:?}", e);
            thread::sleep(Duration::from_micros(1));
        }
        Err(IOError::new(ErrorKind::Other, error))
    }

    pub fn recv_timeout(socket: &zmq::Socket, timeout: usize) -> IOResult<()> {
        let mut error = String::new();
        for _ in 0..timeout {
            let Err(e) = socket.recv_bytes(1) else {
                return Ok(());
            };
            error = format!("ZeroMQ recv failed: {:?}", e);
            thread::sleep(Duration::from_micros(1));
        }
        Err(IOError::new(ErrorKind::Other, error))
    }

    pub fn send(&mut self, underlay_l2_opt_size: usize, mut packet: Vec<u8>) -> IOResult<usize> {
        self.connect_check()?;

        let overlay_packet_offset = self.overlay_packet_offset + underlay_l2_opt_size;
        let packet = &mut packet.as_mut_slice()[overlay_packet_offset..];
        let mut header = NpbHeader::default();
        let _ = header.decode(packet);
        header.total_length = packet.len() as u16;
        let _ = header.encode(packet);

        let socket = self.socket.take().unwrap();

        let n = Self::send_timeout(&socket, packet.as_bytes(), Self::MAX_TRY_COUNT)?;
        match Self::recv_timeout(&socket, Self::MAX_TRY_COUNT) {
            Ok(()) => {
                self.socket.replace(socket);
                Ok(n)
            }
            Err(e) => Err(e),
        }
    }
}
