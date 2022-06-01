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

use super::{debugger::send_to, Message, Module, MAX_MESSAGE_SIZE, SESSION_TIMEOUT};

use crate::utils::queue::{Error, Receiver};

const QUEUE_RELEASE_TIMEOUT: Duration = Duration::from_micros(1);
const QUEUE_RECV_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum QueueMessage {
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
    pub(crate) fn new() -> Self {
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
                    while let Ok(_) = ctx.receiver.recv(Some(QUEUE_RELEASE_TIMEOUT)) {}
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
            .iter()
            .map(|(&c, ctx)| (String::from(c), ctx.enabled.load(Ordering::Relaxed)))
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
        let ctx = {
            let guard = self.queues.lock().unwrap();
            if let Some(ctx) = guard.get(name.as_str()) {
                // queue已经被占用接收数据，返回错误
                if ctx.already_used.load(Ordering::Relaxed) {
                    let msg = Message {
                        module: Module::Queue,
                        msg: QueueMessage::Err(format!("queue {} already used", name)),
                    };
                    let _ = send_to(&sock, conn, &msg);
                    return;
                }

                ctx.already_used.swap(true, Ordering::Relaxed);

                ctx.clone()
            } else {
                let msg = Message {
                    module: Module::Queue,
                    msg: QueueMessage::Err(format!("queue {} not exist", name)),
                };
                let _ = send_to(&sock, conn, &msg);
                return;
            }
        };
        let queue_name = name.clone();
        let handle = thread::spawn(move || {
            let now = Instant::now();
            let mut session_timeout = SESSION_TIMEOUT - Duration::from_secs(1);

            while ctx.enabled.load(Ordering::SeqCst) && now.elapsed() < dur {
                let s = match ctx.receiver.recv(Some(QUEUE_RECV_TIMEOUT)) {
                    Ok(s) => s,
                    Err(Error::Terminated(..)) => {
                        ctx.already_used.swap(false, Ordering::Relaxed);
                        ctx.enabled.swap(false, Ordering::Relaxed);

                        let msg = Message {
                            module: Module::Queue,
                            msg: QueueMessage::Err(format!(
                                "queue {} already terminated",
                                queue_name
                            )),
                        };
                        let _ = send_to(&sock, conn, &msg);
                        return;
                    }
                    Err(Error::Timeout) => {
                        // 一个UDP会话超时还没有数据，就发送消息让客户端继续等待
                        if now.elapsed() > session_timeout {
                            let msg = Message {
                                module: Module::Queue,
                                msg: QueueMessage::Continue,
                            };
                            let _ = send_to(&sock, conn, &msg);
                            session_timeout += SESSION_TIMEOUT;
                        }
                        continue;
                    }
                };

                if s.len() > MAX_MESSAGE_SIZE {
                    // String::truncate 削到char的边界的时候会panic
                    let mut c = s.into_bytes();
                    c.truncate(MAX_MESSAGE_SIZE);
                    if let Ok(s) = String::from_utf8(c) {
                        let msg = Message {
                            module: Module::Queue,
                            msg: QueueMessage::Send(s),
                        };
                        let _ = send_to(&sock, conn, &msg);
                    }
                } else {
                    let msg = Message {
                        module: Module::Queue,
                        msg: QueueMessage::Send(s),
                    };
                    let _ = send_to(&sock, conn, &msg);
                }
            }
            ctx.already_used.swap(false, Ordering::Relaxed);

            let msg = Message {
                module: Module::Queue,
                msg: QueueMessage::Fin,
            };
            let _ = send_to(&sock, conn, &msg);
        });
        self.threads.lock().unwrap().insert(name, handle);
    }

    fn change_running(&self, name: impl AsRef<str>, state: bool) -> Message<QueueMessage> {
        let name = name.as_ref();

        let mut guard = self.queues.lock().unwrap();
        match guard.remove_entry(name) {
            Some((name, ctx)) => {
                if !ctx.receiver.terminated() {
                    ctx.enabled.store(state, Ordering::SeqCst);
                    // release queue item
                    while let Ok(_) = ctx.receiver.recv(Some(QUEUE_RELEASE_TIMEOUT)) {}
                    guard.insert(name, ctx);
                    Message {
                        module: Module::Queue,
                        msg: QueueMessage::Fin,
                    }
                } else {
                    self.threads.lock().unwrap().remove(name);
                    Message {
                        module: Module::Queue,
                        msg: QueueMessage::Err(format!("queue {} already terminated", name)),
                    }
                }
            }
            None => Message {
                module: Module::Queue,
                msg: QueueMessage::Err(format!("queue {} not exist", name)),
            },
        }
    }
}
