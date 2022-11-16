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

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bincode::{config::Configuration, Decode, Encode};
use log::warn;

use crate::policy::PolicySetter;
use public::{
    debug::send_to,
    queue::{bounded, Error, Receiver, Sender},
};

#[derive(PartialEq, Debug, Encode, Decode)]
pub enum PolicyMessage {
    Unknown,
    On,
    Off,
    Title(String),
    Context(String),
    Show,
    Analyzing(u32),
    Done,
    Err(String),
}

pub struct PolicyDebugger {
    policy_setter: PolicySetter,
    sender: Arc<Sender<String>>,
    receiver: Arc<Receiver<String>>,
    enabled: Arc<AtomicBool>,
}

impl PolicyDebugger {
    const QUEUE_RECV_TIMEOUT: Duration = Duration::from_secs(1);

    pub fn new(mut policy_setter: PolicySetter) -> Self {
        let (sender, receiver, _) = bounded(1024);
        let sender = Arc::new(sender);
        let enabled = Arc::new(AtomicBool::new(false));

        policy_setter.set_monitor(sender.clone(), enabled.clone());

        PolicyDebugger {
            enabled,
            sender,
            receiver: Arc::new(receiver),
            policy_setter,
        }
    }

    pub(super) fn turn_off(&self) {
        self.enabled.swap(false, Ordering::Relaxed);
    }

    pub(super) fn turn_on(&self) {
        self.enabled.swap(true, Ordering::Relaxed);
    }

    pub(super) fn send(&self, sock: &UdpSocket, conn: SocketAddr, serialize_conf: Configuration) {
        let now = Instant::now();
        let duration = Duration::from_secs(30);

        self.turn_on();

        while self.enabled.load(Ordering::SeqCst) && now.elapsed() < duration {
            let s = match self.receiver.recv(Some(Self::QUEUE_RECV_TIMEOUT)) {
                Ok(s) => s,
                Err(Error::Terminated(..)) => {
                    self.turn_off();
                    let _ = send_to(
                        &sock,
                        conn,
                        PolicyMessage::Err("policy monitor queue terminated.".to_string()),
                        serialize_conf,
                    );
                    return;
                }
                Err(Error::Timeout) => continue,
            };

            if let Err(e) = send_to(&sock, conn, PolicyMessage::Context(s), serialize_conf) {
                warn!("send policy item error: {}", e);
            }
        }
        self.turn_off();

        let _ = send_to(&sock, conn, PolicyMessage::Done, serialize_conf);
    }

    pub(super) fn show(&self, sock: &UdpSocket, conn: SocketAddr, serialize_conf: Configuration) {
        let mut acls = self.policy_setter.get_acls().clone();
        let (first_hits, fast_hits) = self.policy_setter.get_hits();
        acls.sort_by_key(|x| x.id);
        let _ = send_to(
            &sock,
            conn,
            PolicyMessage::Title(format!(
                "FirstPath Hits: {}, FastPath Hits: {}",
                first_hits, fast_hits
            )),
            serialize_conf,
        );
        for acl in acls {
            let _ = send_to(
                &sock,
                conn,
                PolicyMessage::Context(acl.to_string()),
                serialize_conf,
            );
        }
        let _ = send_to(&sock, conn, PolicyMessage::Done, serialize_conf);
    }

    pub(super) fn analyzing(
        &self,
        sock: &UdpSocket,
        conn: SocketAddr,
        id: u32,
        serialize_conf: Configuration,
    ) {
        let acl = self.policy_setter.get_acls().iter().find(|&x| x.id == id);
        if acl.is_none() {
            let _ = send_to(
                &sock,
                conn,
                PolicyMessage::Context(format!("Invalid acl id {}.", id)),
                serialize_conf,
            );
            return;
        }
        let groups = self.policy_setter.get_groups();
        let acl = acl.unwrap();
        let mut src_groups = Vec::new();
        let mut dst_groups = Vec::new();

        for group_id in &acl.src_groups {
            let src_group = groups.iter().find(|x| x.id == *group_id as u16);
            if src_group.is_some() {
                src_groups.push(src_group.unwrap().clone());
            }
        }
        for group_id in &acl.dst_groups {
            let dst_group = groups.iter().find(|x| x.id == *group_id as u16);
            if dst_group.is_some() {
                dst_groups.push(dst_group.unwrap().clone());
            }
        }

        let _ = send_to(&sock, conn, PolicyMessage::Context(format!(
            "Id: {}\nTapType: {}\nIP Src: \n\t{}\nIP Dst: \n\t{}\nProtocol: {}\nPort Src: {:?}\nPort Dst: {:?}\nActions: {}\n", acl.id,acl.tap_type,src_groups.iter().map(|x| format!("EPC: {} IP: {:?}", x.epc_id, x.ips)).collect::<Vec<String>>().join("\t\n"),dst_groups.iter().map(|x| format!("EPC: {} IP: {:?}", x.epc_id, x.ips)).collect::<Vec<String>>().join("\t\n"),
            acl.proto,
            acl.src_port_ranges.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(", "),
            acl.dst_port_ranges.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(", "),
            acl.npb_actions.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(","),
        )), serialize_conf);
    }
}
