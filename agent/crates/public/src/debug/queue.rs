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

use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    str,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use bincode::{config::Configuration, encode_to_vec, Decode, Encode};
use log::warn;

use super::{Error as SendError, Result, DEBUG_QUEUE_IDLE_TIMEOUT, MAX_BUF_SIZE};
use crate::queue::{Error, Receiver};

const QUEUE_RELEASE_TIMEOUT: Duration = Duration::from_micros(1);
const QUEUE_RECV_TIMEOUT: Duration = Duration::from_secs(1);

pub fn send_to(
    sock: &UdpSocket,
    addr: impl ToSocketAddrs + Clone,
    msg: impl Encode,
    conf: Configuration,
) -> Result<()> {
    let encoded = encode_to_vec(msg, conf)?;
    if encoded.len() > MAX_BUF_SIZE {
        return Err(SendError::IoError(io::Error::new(
            ErrorKind::Other,
            "too large packets to send",
        )));
    }
    sock.send_to(encoded.as_slice(), addr)?;
    Ok(())
}

#[derive(PartialEq, Debug, Encode, Decode)]
pub enum QueueMessage {
    Unknown,
    // None 表示请求， Some表示响应
    Names(Option<Vec<(String, bool)>>),
    // 请求queue name, 发送queue item
    Send(String),
    On((String, Duration)),
    Off(String),
    Continue,
    Clear,
    Fin,
    // 如果queue已经关闭，发送关闭消息
    Err(String),
}

#[derive(Clone)]
struct QueueContext {
    receiver: Arc<Receiver<String>>,
    enabled: Arc<AtomicBool>,
    already_used: Arc<AtomicBool>,
}

pub struct QueueDebugger {
    // receiver 如果接收到错误就从hashmap删除
    queues: Mutex<HashMap<&'static str, QueueContext>>,
    threads: Mutex<HashMap<String, JoinHandle<()>>>,
}

impl QueueDebugger {
    pub fn new() -> Self {
        Self {
            queues: Mutex::new(HashMap::new()),
            threads: Mutex::new(HashMap::new()),
        }
    }

    pub fn append_queue(
        &self,
        name: &'static str,
        queue: Receiver<String>,
        enabled: Arc<AtomicBool>,
    ) {
        let ctx = QueueContext {
            receiver: Arc::new(queue),
            enabled,
            already_used: Arc::new(AtomicBool::new(false)),
        };
        self.queues.lock().unwrap().insert(name, ctx);
    }

    pub fn turn_on_queue(&self, name: impl AsRef<str>) -> QueueMessage {
        self.change_running(name, true)
    }

    pub fn turn_off_queue(&self, name: impl AsRef<str>) -> QueueMessage {
        self.change_running(name, false)
    }

    pub fn turn_off_all_queue(&self) -> QueueMessage {
        let mut threads = self.threads.lock().unwrap();
        self.queues.lock().unwrap().retain(|name, ctx| {
            if !ctx.receiver.terminated() {
                ctx.enabled.store(false, Ordering::SeqCst);
                // release queue item
                while let Ok(_) = ctx.receiver.recv(Some(QUEUE_RELEASE_TIMEOUT)) {}
                true
            } else {
                threads.remove(*name);
                false
            }
        });
        QueueMessage::Fin
    }

    pub fn queue_names(&self) -> Vec<QueueMessage> {
        let mut names = self
            .queues
            .lock()
            .unwrap()
            .iter()
            .map(|(&c, ctx)| (String::from(c), ctx.enabled.load(Ordering::Relaxed)))
            .collect::<Vec<_>>();
        names.sort();
        vec![QueueMessage::Names(Some(names)), QueueMessage::Fin]
    }

    pub fn send(
        &self,
        name: impl Into<String>,
        conn: SocketAddr,
        serialize_conf: Configuration,
        dur: Duration,
    ) {
        let name = name.into();
        let sock = match UdpSocket::bind((IpAddr::from(Ipv6Addr::UNSPECIFIED), 0)) {
            Ok(s) => s,
            Err(last_error) => match UdpSocket::bind((IpAddr::from(Ipv4Addr::UNSPECIFIED), 0)) {
                Ok(s) => s,
                Err(e) => {
                    warn!("UdpSocket::bind with ipv6 address error: {}", last_error);
                    warn!("UdpSocket::bind with ipv4 address error: {}", e);
                    return;
                }
            },
        };
        let ctx = {
            let guard = self.queues.lock().unwrap();
            if let Some(ctx) = guard.get(name.as_str()) {
                // queue已经被占用接收数据，返回错误
                if ctx.already_used.load(Ordering::Relaxed) {
                    let msg = QueueMessage::Err(format!("queue {} already used", name));
                    let _ = send_to(&sock, conn, msg, serialize_conf);
                    return;
                }
                ctx.already_used.swap(true, Ordering::Relaxed);
                ctx.clone()
            } else {
                let msg = QueueMessage::Err(format!("queue {} not exist", name));
                let _ = send_to(&sock, conn, msg, serialize_conf);
                return;
            }
        };
        let queue_name = name.clone();
        let handle = thread::Builder::new()
            .name("queue-debugger".to_owned())
            .spawn(move || {
                let now = Instant::now();

                let mut idle_now = Instant::now();
                let mut msg_counter = 0;
                while ctx.enabled.load(Ordering::SeqCst) && now.elapsed() < dur {
                    let s = match ctx.receiver.recv(Some(QUEUE_RECV_TIMEOUT)) {
                        Ok(s) => s,
                        Err(Error::Terminated(..)) => {
                            ctx.already_used.swap(false, Ordering::Relaxed);
                            ctx.enabled.swap(false, Ordering::Relaxed);
                            let msg = QueueMessage::Err(format!(
                                "queue {} already terminated",
                                queue_name
                            ));
                            let _ = send_to(&sock, conn, msg, serialize_conf);
                            return;
                        }
                        Err(Error::Timeout) => {
                            // 一个IDLE超时还没有数据，就发送消息让客户端继续等待
                            // An IDLE timeout and there is no data, send a message to let the client continue to wait
                            if idle_now.elapsed() > DEBUG_QUEUE_IDLE_TIMEOUT && msg_counter == 0 {
                                let _ =
                                    send_to(&sock, conn, QueueMessage::Continue, serialize_conf);
                                idle_now = Instant::now();
                            }
                            msg_counter = 0;
                            continue;
                        }
                        Err(Error::BatchTooLarge(_)) => unreachable!(),
                    };
                    msg_counter += 1;
                    let msg = QueueMessage::Send(s);
                    if let Err(e) = send_to(&sock, conn, msg, serialize_conf) {
                        warn!("send queue item error: {}", e);
                    }
                }
                ctx.already_used.swap(false, Ordering::Relaxed);
                let msg = QueueMessage::Fin;
                let _ = send_to(&sock, conn, msg, serialize_conf);
            })
            .unwrap();
        self.threads.lock().unwrap().insert(name, handle);
    }

    fn change_running(&self, name: impl AsRef<str>, state: bool) -> QueueMessage {
        let name = name.as_ref();

        let mut guard = self.queues.lock().unwrap();
        match guard.remove_entry(name) {
            Some((name, ctx)) => {
                if !ctx.receiver.terminated() {
                    ctx.enabled.store(state, Ordering::SeqCst);
                    // release queue item
                    while let Ok(_) = ctx.receiver.recv(Some(QUEUE_RELEASE_TIMEOUT)) {}
                    guard.insert(name, ctx);

                    QueueMessage::Fin
                } else {
                    self.threads.lock().unwrap().remove(name);
                    QueueMessage::Err(format!("queue {} already terminated", name))
                }
            }
            None => QueueMessage::Err(format!("queue {} not exist", name)),
        }
    }
}
