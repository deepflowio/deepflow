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
    borrow::Cow,
    cell::OnceCell,
    collections::VecDeque,
    fmt,
    fs::File,
    io::Result as IoResult,
    ops::Deref,
    path::PathBuf,
    pin::Pin,
    process::{self, Output},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::{future::BoxFuture, stream::Stream};
use log::{debug, info, trace, warn};
use md5::{Digest, Md5};
use parking_lot::RwLock;
use tokio::{
    process::Command as TokioCommand,
    runtime::Runtime,
    sync::mpsc::{self, Receiver},
    time::{self, Interval},
};

use super::{Session, RPC_RETRY_INTERVAL};
use crate::trident::AgentId;

use public::{
    netns::{reset_netns, set_netns},
    proto::trident as pb,
};

const MIN_BATCH_LEN: usize = 1024;

enum OutputFormat {
    Text,
    Binary,
}

enum CommandType {
    Linux,
    Kubernetes,
}

struct Command {
    cmdline: &'static str,
    output_format: OutputFormat,
    desc: &'static str,
    command_type: CommandType,
}

fn all_supported_commands() -> Vec<Command> {
    vec![
        Command {
            cmdline: "lsns",
            output_format: OutputFormat::Text,
            desc: "",
            command_type: CommandType::Linux,
        },
        Command {
            cmdline: "top -b -n 1 -c",
            output_format: OutputFormat::Text,
            desc: "top",
            command_type: CommandType::Linux,
        },
        Command {
            cmdline: "ps auxf",
            output_format: OutputFormat::Text,
            desc: "ps",
            command_type: CommandType::Linux,
        },
        Command {
            cmdline: "ip address",
            output_format: OutputFormat::Text,
            desc: "",
            command_type: CommandType::Linux,
        },
        Command {
            cmdline: "kubectl -n $ns describe pod $pod",
            output_format: OutputFormat::Text,
            desc: "",
            command_type: CommandType::Kubernetes,
        },
        Command {
            cmdline: "kubectl -n $ns logs --tail=10000 $pod",
            output_format: OutputFormat::Text,
            desc: "",
            command_type: CommandType::Kubernetes,
        },
        Command {
            cmdline: "kubectl -n $ns logs --tail=10000 -p $pod",
            output_format: OutputFormat::Text,
            desc: "",
            command_type: CommandType::Kubernetes,
        },
    ]
}

thread_local! {
    static SUPPORTED_COMMANDS: OnceCell<Vec<Command>> = OnceCell::new();
    static MAX_PARAM_NUMS: OnceCell<usize> = OnceCell::new();
}

fn get_cmdline(id: usize) -> Option<&'static str> {
    SUPPORTED_COMMANDS.with(|cell| {
        let cs = cell.get_or_init(|| all_supported_commands());
        cs.get(id).map(|c| c.cmdline)
    })
}

fn max_param_nums() -> usize {
    MAX_PARAM_NUMS.with(|p| {
        *p.get_or_init(|| {
            SUPPORTED_COMMANDS.with(|cell| {
                let cs = cell.get_or_init(|| all_supported_commands());
                // count number of dollar args
                cs.iter()
                    .map(|c| {
                        c.cmdline
                            .split_whitespace()
                            .into_iter()
                            .map(|seg| if seg.starts_with('$') { 1 } else { 0 })
                            .sum::<usize>()
                    })
                    .max()
                    .unwrap_or_default()
            })
        })
    })
}

struct NetNsInfo {
    id: u64,
    user: String,
    pid: u32,
    cmd: String,
}

impl From<NetNsInfo> for pb::LinuxNamespace {
    fn from(c: NetNsInfo) -> Self {
        Self {
            id: Some(c.id),
            ns_type: Some("net".to_owned()),
            user: Some(c.user),
            pid: Some(c.pid),
            cmd: Some(c.cmd),
        }
    }
}

struct Interior {
    agent_id: Arc<RwLock<AgentId>>,
    session: Arc<Session>,
    running: Arc<AtomicBool>,
}

impl Interior {
    async fn run(&mut self) {
        let mut server_responded = true;
        while self.running.load(Ordering::Relaxed) {
            if !server_responded {
                // sleep here to avoid flooding server without RemoteExec implemented
                tokio::time::sleep(RPC_RETRY_INTERVAL).await;
            }
            server_responded = false;

            let (sender, receiver) = mpsc::channel(1);
            let responser = Responser::new(self.agent_id.clone(), receiver);

            self.session.update_current_server().await;
            let client = match self.session.get_client() {
                Some(c) => c,
                None => {
                    self.session.set_request_failed(true);
                    tokio::time::sleep(RPC_RETRY_INTERVAL).await;
                    continue;
                }
            };
            let mut client = pb::synchronizer_client::SynchronizerClient::new(client);

            let now = Instant::now();
            trace!("remote_execute call");

            let mut stream = match client.remote_execute(responser).await {
                Ok(stream) => stream,
                Err(e) => {
                    warn!("remote_execute failed: {:?}", e);
                    tokio::time::sleep(RPC_RETRY_INTERVAL).await;
                    continue;
                }
            }
            .into_inner();
            trace!("remote_execute initial receive");
            debug!("remote_execute latency {:?}ms", now.elapsed().as_millis());

            while let Ok(Some(message)) = stream.message().await {
                server_responded = true;
                if !self.running.load(Ordering::Relaxed) {
                    break;
                }
                if message.exec_type.is_none() {
                    continue;
                }
                match pb::ExecutionType::from_i32(message.exec_type.unwrap()) {
                    Some(t) => debug!("received {:?} command from server", t),
                    None => {
                        warn!(
                            "unsupported remote exec type id {}",
                            message.exec_type.unwrap()
                        );
                        continue;
                    }
                }
                if sender.send(message).await.is_err() {
                    debug!("responser channel closed");
                    break;
                }
            }
        }
    }
}

pub struct Executor {
    agent_id: Arc<RwLock<AgentId>>,
    session: Arc<Session>,
    runtime: Arc<Runtime>,

    running: Arc<AtomicBool>,
}

impl Executor {
    pub fn new(
        agent_id: Arc<RwLock<AgentId>>,
        session: Arc<Session>,
        runtime: Arc<Runtime>,
    ) -> Self {
        Self {
            agent_id,
            session,
            runtime,
            running: Default::default(),
        }
    }

    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut interior = Interior {
            agent_id: self.agent_id.clone(),
            session: self.session.clone(),
            running: self.running.clone(),
        };
        self.runtime.spawn(async move {
            interior.run().await;
        });
        info!("Started remote executor");
    }

    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return;
        }
        info!("Stopped remote executor");
    }
}

#[derive(Default)]
struct CommandResult {
    errno: i32,
    output: VecDeque<u8>,
    total_len: usize,
    digest: Md5,
}

struct Responser {
    agent_id: Arc<RwLock<AgentId>>,
    batch_len: usize,

    heartbeat: Interval,
    msg_recv: Receiver<pb::RemoteExecRequest>,

    pending_lsns: Option<BoxFuture<'static, Vec<pb::LinuxNamespace>>>,

    pending_command: Option<(usize, Option<File>, BoxFuture<'static, IoResult<Output>>)>,
    result: CommandResult,
}

impl Responser {
    fn new(agent_id: Arc<RwLock<AgentId>>, receiver: Receiver<pb::RemoteExecRequest>) -> Self {
        Responser {
            agent_id: agent_id,
            batch_len: pb::RemoteExecRequest::default().batch_len() as usize,
            heartbeat: time::interval(Duration::from_secs(30)),
            msg_recv: receiver,
            pending_lsns: None,
            pending_command: None,
            result: CommandResult::default(),
        }
    }

    fn generate_result_batch(&mut self) -> Option<pb::CommandResult> {
        let batch_len = self.batch_len;
        let r = &mut self.result;
        if r.output.is_empty() {
            return None;
        }

        let mut pb_result = pb::CommandResult {
            errno: Some(r.errno),
            total_len: Some(r.total_len as u64),
            pkt_count: Some((r.total_len.saturating_sub(1) / batch_len + 1) as u32),
            ..Default::default()
        };
        let last = r.output.len() <= batch_len;
        if last {
            let content = r.output.drain(..).collect::<Vec<_>>();
            r.digest.update(&content[..]);
            pb_result.content = Some(content);
            pb_result.md5 = Some(format!("{:x}", r.digest.finalize_reset()));
        } else {
            let content = r.output.drain(..batch_len).collect::<Vec<_>>();
            r.digest.update(&content[..]);
            pb_result.content = Some(content);
        }
        Some(pb_result)
    }

    fn command_failed_helper<'a, S: Into<Cow<'a, str>>>(
        &self,
        code: Option<i32>,
        msg: S,
    ) -> Poll<Option<pb::RemoteExecResponse>> {
        let msg: Cow<str> = msg.into();
        warn!("{}", msg);
        Poll::Ready(Some(pb::RemoteExecResponse {
            agent_id: Some(self.agent_id.read().deref().into()),
            command_result: Some(pb::CommandResult {
                errno: code,
                errmsg: Some(msg.into_owned()),
                ..Default::default()
            }),
            ..Default::default()
        }))
    }
}

impl Stream for Responser {
    type Item = pb::RemoteExecResponse;

    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        /*
         * order of polling:
         * 1. Send remaining buffered command output
         * 2. Poll pending command if any. If command succeeded, restart from top
         * 3. Poll pending lsns function if any
         * 4. Poll message queue for command from server. On receiving a new command, restart from top
         * 5. Poll ticker for heartbeat
         */

        loop {
            if let Some(batch) = self.as_mut().generate_result_batch() {
                trace!(
                    "send buffer {} bytes",
                    batch.content.as_ref().unwrap().len()
                );
                return Poll::Ready(Some(pb::RemoteExecResponse {
                    agent_id: Some(self.agent_id.read().deref().into()),
                    command_result: Some(batch),
                    ..Default::default()
                }));
            }

            if let Some((id, ns_fp, future)) = self.pending_command.as_mut() {
                trace!("poll pending command '{}'", get_cmdline(*id).unwrap());
                if let Some(f) = ns_fp {
                    if let Err(e) = set_netns(f) {
                        warn!(
                            "set_netns failed when executing {}: {}",
                            get_cmdline(*id).unwrap(),
                            e
                        );
                    }
                }
                let p = future.as_mut().poll(ctx);
                if ns_fp.is_some() {
                    if let Err(e) = reset_netns() {
                        warn!(
                            "reset_netns failed when executing {}: {}",
                            get_cmdline(*id).unwrap(),
                            e
                        );
                    }
                }

                if let Poll::Ready(res) = p {
                    let (id, _, _) = self.pending_command.take().unwrap();
                    match res {
                        Ok(output) if output.status.success() => {
                            debug!("command '{}' succeeded", get_cmdline(id).unwrap());
                            if output.stdout.is_empty() {
                                return Poll::Ready(Some(pb::RemoteExecResponse {
                                    agent_id: Some(self.agent_id.read().deref().into()),
                                    command_result: Some(pb::CommandResult::default()),
                                    ..Default::default()
                                }));
                            }
                            let r = &mut self.result;
                            r.errno = 0;
                            r.output = output.stdout.into();
                            r.total_len = r.output.len();
                            r.digest.reset();
                            continue;
                        }
                        Ok(output) => {
                            if let Some(code) = output.status.code() {
                                return self.command_failed_helper(
                                    Some(code),
                                    format!(
                                        "command '{}' failed with {}",
                                        get_cmdline(id).unwrap(),
                                        code
                                    ),
                                );
                            } else {
                                return self.command_failed_helper(
                                    None,
                                    format!(
                                        "command '{}' execute terminated without errno",
                                        get_cmdline(id).unwrap()
                                    ),
                                );
                            }
                        }
                        Err(e) => {
                            return self.command_failed_helper(
                                None,
                                format!(
                                    "command '{}' execute failed: {}",
                                    get_cmdline(id).unwrap(),
                                    e
                                ),
                            )
                        }
                    }
                }
            }

            if let Some(future) = self.pending_lsns.as_mut() {
                trace!("poll pending lsns");
                if let Poll::Ready(namespaces) = future.as_mut().poll(ctx) {
                    debug!("list namespace completed with {} entries", namespaces.len());
                    self.pending_lsns.take();
                    return Poll::Ready(Some(pb::RemoteExecResponse {
                        agent_id: Some(self.agent_id.read().deref().into()),
                        linux_namespaces: namespaces,
                        ..Default::default()
                    }));
                }
            }

            match self.msg_recv.poll_recv(ctx) {
                // sender closed, terminate the current stream
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(msg)) => {
                    match pb::ExecutionType::from_i32(msg.exec_type.unwrap()).unwrap() {
                        pb::ExecutionType::ListCommand => {
                            let mut commands = vec![];
                            SUPPORTED_COMMANDS.with(|cell| {
                                let cs = cell.get_or_init(|| all_supported_commands());
                                for (id, c) in cs.iter().enumerate() {
                                    commands.push(pb::RemoteCommand {
                                        id: Some(id as u32),
                                        cmd: if c.desc.is_empty() {
                                            Some(c.cmdline.to_owned())
                                        } else {
                                            Some(c.desc.to_owned())
                                        },
                                        param_names: c
                                            .cmdline
                                            .split_whitespace()
                                            .filter_map(|seg| {
                                                if seg.starts_with("$") {
                                                    Some(seg.split_at(1).1.to_owned())
                                                } else {
                                                    None
                                                }
                                            })
                                            .collect(),
                                        output_format: match c.output_format {
                                            OutputFormat::Text => {
                                                Some(pb::OutputFormat::Text as i32)
                                            }
                                            OutputFormat::Binary => {
                                                Some(pb::OutputFormat::Binary as i32)
                                            }
                                        },
                                        cmd_type: match c.command_type {
                                            CommandType::Linux => {
                                                Some(pb::CommandType::Linux as i32)
                                            }
                                            CommandType::Kubernetes => {
                                                Some(pb::CommandType::Kubernetes as i32)
                                            }
                                        },
                                    });
                                }
                            });
                            debug!("list command returning {} entries", commands.len());
                            return Poll::Ready(Some(pb::RemoteExecResponse {
                                agent_id: Some(self.agent_id.read().deref().into()),
                                commands,
                                ..Default::default()
                            }));
                        }
                        pb::ExecutionType::ListNamespace => {
                            trace!("pending list namespace");
                            self.pending_lsns = Some(Box::pin(lsns()));
                            continue;
                        }
                        pb::ExecutionType::RunCommand => {
                            if let Some(batch_len) = msg.batch_len {
                                self.batch_len = MIN_BATCH_LEN.max(batch_len as usize);
                            }
                            let Some(cmdline) =
                                msg.command_id.and_then(|id| get_cmdline(id as usize))
                            else {
                                return self.command_failed_helper(
                                    None,
                                    "command_id not specified or invalid in run command request",
                                );
                            };
                            let params =
                                Params(&msg.params[..msg.params.len().min(max_param_nums())]);
                            if !params.is_valid() {
                                return self.command_failed_helper(
                                    None,
                                    format!(
                                        "rejected run command '{}' with invalid params: {:?}",
                                        cmdline, params
                                    ),
                                );
                            }

                            let nsfile_fp = match msg.linux_ns_pid {
                                Some(pid) if pid != process::id() => {
                                    let path: PathBuf =
                                        ["/proc", &pid.to_string(), "ns", "net"].iter().collect();
                                    match File::open(&path) {
                                        Ok(fp) => Some(fp),
                                        Err(e) => {
                                            return self.command_failed_helper(
                                                None,
                                                format!(
                                                    "open namespace file {} failed: {}",
                                                    path.display(),
                                                    e
                                                ),
                                            )
                                        }
                                    }
                                }
                                _ => None,
                            };

                            trace!(
                                "pending run command '{}', ns_pid: {:?}, params: {:?}",
                                cmdline,
                                msg.linux_ns_pid,
                                params
                            );

                            // split the whole command line to enable PATH lookup
                            let mut args = cmdline.split_whitespace();
                            let mut cmd = TokioCommand::new(args.next().unwrap());
                            for arg in args {
                                if arg.starts_with('$') {
                                    let name = arg.split_at(1).1;
                                    match params
                                        .0
                                        .iter()
                                        .position(|p| p.key.as_ref().unwrap() == name)
                                    {
                                        Some(pos) => {
                                            cmd.arg(params.0[pos].value.as_ref().unwrap());
                                        }
                                        None => {
                                            return self.command_failed_helper(
                                                None,
                                                format!(
                                                    "parameter {} not found in command '{}'",
                                                    arg, cmdline
                                                ),
                                            )
                                        }
                                    }
                                } else {
                                    cmd.arg(arg);
                                }
                            }
                            self.pending_command = Some((
                                msg.command_id.unwrap() as usize,
                                nsfile_fp,
                                Box::pin(cmd.output()),
                            ));
                            continue;
                        }
                    }
                }
                _ => (),
            }

            return match self.heartbeat.poll_tick(ctx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(_) => Poll::Ready(Some(pb::RemoteExecResponse {
                    agent_id: Some(self.agent_id.read().deref().into()),
                    ..Default::default()
                })),
            };
        }
    }
}

async fn lsns() -> Vec<pb::LinuxNamespace> {
    let output = TokioCommand::new("lsns")
        .args([
            "--list",
            "--type",
            "net",
            "--noheadings",
            "--output",
            "NS,PID,USER,COMMAND",
        ])
        .output()
        .await;
    let output = match output {
        Ok(o) => o,
        Err(e) => {
            warn!("command failed: {}", e);
            return vec![];
        }
    };
    if !output.status.success() {
        warn!("lsns failed with {}", output.status);
        return vec![];
    }
    let mut namespaces = vec![];
    for line in output.stdout.split(|c| *c == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        trace!("lsns parse line {}", line);
        let mut segs = line.trim().split_whitespace();

        let id = segs.next().and_then(|s| s.trim().parse::<u64>().ok());
        let pid = segs.next().and_then(|s| s.trim().parse::<u32>().ok());
        let user = segs.next().map(|s| s.trim().to_owned());
        let cmd = segs.next().map(|s| s.trim().to_owned());

        if id.is_none() || pid.is_none() || user.is_none() || cmd.is_none() {
            continue;
        }
        namespaces.push(pb::LinuxNamespace {
            id,
            pid,
            user,
            cmd,
            ns_type: Some("net".to_owned()),
        });
    }
    namespaces
}

struct Params<'a>(&'a [pb::Parameter]);

impl Params<'_> {
    fn is_valid(&self) -> bool {
        for p in self.0.iter() {
            if p.key.is_none() {
                return false;
            }
            let Some(value) = p.value.as_ref() else {
                return false;
            };
            for c in value.as_bytes() {
                match c {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => (),
                    _ => return false,
                }
            }
        }
        true
    }
}

impl fmt::Debug for Params<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{")?;
        let mut empty = true;
        for p in self.0.iter() {
            let Some(key) = p.key.as_ref() else {
                continue;
            };
            if empty {
                write!(f, " ")?;
            } else {
                write!(f, ", ")?;
            }
            if let Some(value) = p.value.as_ref() {
                write!(f, "{}: \"{}\"", key, value)?;
            } else {
                write!(f, "{}: null", key)?;
            }
            empty = false;
        }
        if !empty {
            write!(f, " ")?;
        }
        write!(f, "}}")
    }
}
