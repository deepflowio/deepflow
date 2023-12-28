/*
 * Copyright (c) 2023 Yunshan Networks
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

use std::pin::Pin;
use std::process::Stdio;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::task::{Context, Poll, Waker};

use log::{debug, trace, warn};
use md5::{Digest, Md5};
use parking_lot::RwLock;
use tokio::{
    process::{Child, Command},
    runtime::Runtime,
    task::JoinHandle,
    time::sleep,
};
use tokio_stream::Stream;

use super::session::Session;
use crate::trident::AgentId;
use public::proto::trident;

const STREAM_BULK_SIZE: usize = 16384;

enum State {
    Hello,
    WaitingForResult,
    SendingOutput,
    Closed,
}

pub struct CommandStream {
    state: State,
    agent_id: AgentId,

    output: Arc<Mutex<Option<Result<Vec<u8>, std::io::Error>>>>,
    offset: usize,
    md5: Vec<u8>,

    waker: Arc<Mutex<Option<Waker>>>,
}

impl CommandStream {
    fn new(agent_id: AgentId) -> Self {
        Self {
            state: State::Hello,
            agent_id,
            output: Default::default(),
            offset: 0,
            md5: Default::default(),
            waker: Default::default(),
        }
    }
}

impl Stream for CommandStream {
    type Item = trident::CommandResponse;

    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.state {
            State::Hello => {
                self.state = State::WaitingForResult;
                trace!("initial message to server");
                return Poll::Ready(Some(trident::CommandResponse {
                    ctrl_mac: Some(self.agent_id.mac.to_string()),
                    ctrl_ip: Some(self.agent_id.ip.to_string()),
                    ..Default::default()
                }));
            }
            State::WaitingForResult if self.output.lock().unwrap().is_none() => {
                trace!("wait for result");
                self.waker.lock().unwrap().replace(ctx.waker().clone());
                return Poll::Pending;
            }
            State::Closed => return Poll::Ready(None),
            _ => (),
        }
        self.state = State::SendingOutput;
        trace!("data is ready");

        let output = self.output.lock().unwrap().take();
        let Ok(content) = output.unwrap() else {
            // case of Err
            self.state = State::Closed;
            return Poll::Ready(Some(trident::CommandResponse {
                ctrl_mac: Some(self.agent_id.mac.to_string()),
                ctrl_ip: Some(self.agent_id.ip.to_string()),
                status: Some(trident::Status::Failed.into()),
                ..Default::default()
            }));
        };

        let total_len = content.len();
        if total_len == 0 {
            self.state = State::Closed;
            return Poll::Ready(None);
        }

        if self.offset == 0 {
            let md5 = Md5::new().chain_update(&content[..]).finalize();
            debug!(
                "will send {} bytes of data to server with md5 {:x}",
                total_len, md5
            );
            self.md5 = md5.to_vec();
        }
        if self.offset + STREAM_BULK_SIZE >= total_len {
            self.state = State::Closed;
        }
        let range = self.offset..(self.offset + STREAM_BULK_SIZE).min(total_len);
        trace!("sending {:?} in a total of {} bytes", range, total_len);
        // we're good here because if self.offset > total_len, next poll will be State::Closed
        self.offset += STREAM_BULK_SIZE;
        let bulk = content[range].to_vec();
        self.output.lock().unwrap().replace(Ok(content));
        return Poll::Ready(Some(trident::CommandResponse {
            ctrl_mac: Some(self.agent_id.mac.to_string()),
            ctrl_ip: Some(self.agent_id.ip.to_string()),
            content: Some(bulk),
            md5: Some(self.md5.clone()),
            total_len: Some(total_len as u64),
            pkt_count: Some(((total_len - 1) / STREAM_BULK_SIZE + 1) as u32),
            ..Default::default()
        }));
    }
}

pub struct Executor {
    agent_id: Arc<RwLock<AgentId>>,
    runtime: Arc<Runtime>,
    session: Arc<Session>,

    running: Arc<AtomicBool>,

    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Executor {
    pub fn new(
        agent_id: Arc<RwLock<AgentId>>,
        runtime: Arc<Runtime>,
        session: Arc<Session>,
    ) -> Self {
        Self {
            agent_id,
            runtime,
            session,
            running: Default::default(),
            thread: Default::default(),
        }
    }

    async fn execute(
        req: trident::CommandRequest,
        output: &mut Vec<u8>,
    ) -> Result<(), std::io::Error> {
        trace!("execute {:?}", req);
        let mut last_child = None;
        for cmd in req.pipeline {
            let mut command = Command::new(cmd.name.unwrap());
            command.args(cmd.arguments);
            if let Some(out) = last_child
                .and_then(|c: Child| c.stdout)
                .and_then(|o| TryInto::<Stdio>::try_into(o).ok())
            {
                command.stdin(out);
            }
            command.stdout(Stdio::piped());

            last_child = Some(command.spawn()?);
        }
        output.extend(last_child.unwrap().wait_with_output().await?.stdout);
        trace!("result {:?}", output);
        Ok(())
    }

    pub fn run(&self) {
        let agent_id = self.agent_id.clone();
        let session = self.session.clone();
        let running = self.running.clone();
        self.thread
            .lock()
            .unwrap()
            .replace(self.runtime.spawn(async move {
                let mut command_output = vec![];
                while running.load(Ordering::SeqCst) {
                    let Some(client) = session.get_client() else {
                        debug!("channel is none");
                        sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    };
                    let mut client = trident::synchronizer_client::SynchronizerClient::new(client);
                    let stream = CommandStream::new(agent_id.read().clone());
                    let output = stream.output.clone();
                    let waker = stream.waker.clone();
                    let mut executed = false;

                    trace!("notify server to send command");
                    let req = match client.command(stream).await {
                        Ok(r) => r,
                        Err(e) => {
                            debug!("command grpc call returns error: {}", e);
                            sleep(std::time::Duration::from_secs(1)).await;
                            continue;
                        }
                    };
                    let mut req = req.into_inner();
                    // the loop exits when server closes the connection
                    while let Ok(Some(message)) = req.message().await {
                        if message.pipeline.is_empty() {
                            trace!("heartbeat from server");
                            continue;
                        }
                        if !executed {
                            executed = true;
                            command_output.clear();
                            debug!("execute command {:?}", message);
                            if let Err(e) = Self::execute(message, &mut command_output).await {
                                warn!("command execution failed {:?}", e);
                                *output.lock().unwrap() = Some(Err(e));
                            } else {
                                *output.lock().unwrap() = Some(Ok(command_output.clone()));
                            }
                        }
                        trace!("notify stream to resume");
                        waker.lock().unwrap().take().map(|w| w.wake());
                    }
                }
            }));
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        self.run();
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        self.runtime.block_on(async move {
            if let Some(t) = self.thread.lock().unwrap().take() {
                let _ = t.await;
            }
        });
    }
}
