use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use super::{debugger::send_to, Message, Module, MAX_MESSAGE_SIZE};

use crate::utils::queue::Receiver;

const QUEUE_RECV_TIMEOUT: Duration = Duration::from_micros(1);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum QueueMessage {
    // None 表示请求， Some表示响应
    Names(Option<Vec<String>>),
    // 请求queue name, 发送queue item
    Send(Vec<String>),
    On((String, Duration)),
    Off(String),
    Clear,
    Fin,
    // 如果queue已经关闭，发送关闭消息
    Err(String),
}

struct QueueContext {
    receiver: Arc<Receiver<String>>,
    enabled: Arc<AtomicBool>,
}

pub struct QueueDebugger {
    // receiver 如果接收到错误就从hashmap删除
    queues: Mutex<HashMap<&'static str, QueueContext>>,
    threads: Mutex<HashMap<String, JoinHandle<()>>>,
}

impl QueueDebugger {
    pub(super) fn new() -> Self {
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
        };
        self.queues.lock().unwrap().insert(name, ctx);
    }

    pub(super) fn turn_on_queue(&self, name: impl AsRef<str>) -> Message<QueueMessage> {
        self.change_running(name, true)
    }

    pub(super) fn turn_off_queue(&self, name: impl AsRef<str>) -> Message<QueueMessage> {
        self.change_running(name, false)
    }

    pub(super) fn turn_off_all_queue(&self) -> Message<QueueMessage> {
        {
            let mut threads = self.threads.lock().unwrap();
            self.queues.lock().unwrap().retain(|name, ctx| {
                if !ctx.receiver.terminated() {
                    ctx.enabled.store(false, Ordering::SeqCst);
                    // release queue item
                    while let Ok(_) = ctx.receiver.recv(Some(QUEUE_RECV_TIMEOUT)) {}
                    true
                } else {
                    threads.remove(*name);
                    false
                }
            });
        }
        Message {
            module: Module::Queue,
            msg: QueueMessage::Fin,
        }
    }

    pub(super) fn queue_names(&self) -> Vec<Message<QueueMessage>> {
        let names = self
            .queues
            .lock()
            .unwrap()
            .keys()
            .map(|&c| String::from(c))
            .collect::<Vec<_>>();
        vec![
            Message {
                module: Module::Queue,
                msg: QueueMessage::Names(Some(names)),
            },
            Message {
                module: Module::Queue,
                msg: QueueMessage::Fin,
            },
        ]
    }

    pub(super) fn send(&self, name: impl Into<String>, conn: SocketAddr, dur: Duration) {
        let name = name.into();
        let sock = UdpSocket::bind(("::", 0)).unwrap();

        let (receiver, running) = {
            let guard = self.queues.lock().unwrap();
            if let Some(ctx) = guard.get(name.as_str()) {
                (ctx.receiver.clone(), ctx.enabled.clone())
            } else {
                let msg = Message {
                    module: Module::Queue,
                    msg: QueueMessage::Err(String::from("queue not exist")),
                };
                let _ = send_to(&sock, conn, &msg);
                return;
            }
        };
        let handle = thread::spawn(move || {
            let now = Instant::now();
            let mut cache = None;
            let mut cache_bytes = 0;
            let mut queue_null = true;
            while running.load(Ordering::SeqCst) && now.elapsed() < dur {
                let s = match receiver.recv(Some(dur)) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                if s.len() > MAX_MESSAGE_SIZE {
                    // String::truncate 削到char的边界的时候会panic
                    let mut c = s.into_bytes();
                    c.truncate(MAX_MESSAGE_SIZE);
                    if let Ok(s) = String::from_utf8(c) {
                        let msg = Message {
                            module: Module::Queue,
                            msg: QueueMessage::Send(vec![s]),
                        };

                        queue_null = send_to(&sock, conn, &msg).is_err();
                    }
                } else if cache_bytes + s.len() < MAX_MESSAGE_SIZE {
                    cache_bytes += s.len();
                    if cache.is_none() {
                        cache.replace(vec![s]);
                    } else {
                        cache.as_mut().unwrap().push(s);
                    }
                } else {
                    let msg = Message {
                        module: Module::Queue,
                        msg: QueueMessage::Send(cache.take().unwrap()),
                    };

                    queue_null = send_to(&sock, conn, &msg).is_err();
                    cache_bytes = s.len();
                    cache.replace(vec![s]);
                }
            }

            if queue_null {
                let msg = Message {
                    module: Module::Queue,
                    msg: QueueMessage::Err(String::from("queue is empty or terminated")),
                };
                let _ = send_to(&sock, conn, &msg);
            } else {
                let msg = Message {
                    module: Module::Queue,
                    msg: QueueMessage::Fin,
                };
                let _ = send_to(&sock, conn, &msg);
            }
        });
        self.threads.lock().unwrap().insert(name, handle);
    }

    fn change_running(&self, name: impl AsRef<str>, state: bool) -> Message<QueueMessage> {
        let name = name.as_ref();

        {
            let mut guard = self.queues.lock().unwrap();
            if let Some((name, ctx)) = guard.remove_entry(name) {
                if !ctx.receiver.terminated() {
                    ctx.enabled.store(state, Ordering::SeqCst);
                    // release queue item
                    while let Ok(_) = ctx.receiver.recv(Some(QUEUE_RECV_TIMEOUT)) {}
                    guard.insert(name, ctx);
                } else {
                    self.threads.lock().unwrap().remove(name);
                }
            }
        }

        Message {
            module: Module::Queue,
            msg: QueueMessage::Fin,
        }
    }
}
