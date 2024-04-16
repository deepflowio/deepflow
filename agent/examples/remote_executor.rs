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

use std::{net::Ipv4Addr, sync::Arc};

use parking_lot::RwLock;
use tokio::runtime::Builder;

use deepflow_agent::{
    exception::ExceptionHandler,
    rpc::{Executor, Session, DEFAULT_TIMEOUT},
    trident::AgentId,
    utils::stats,
};

fn main() {
    flexi_logger::Logger::try_with_env()
        .unwrap()
        .start()
        .unwrap();

    let stats_collector = Arc::new(stats::Collector::new("localhost", Default::default()));
    let session = Arc::new(Session::new(
        20033,
        0,
        DEFAULT_TIMEOUT,
        "".to_owned(),
        vec!["127.0.0.1".to_owned()],
        ExceptionHandler::default(),
        &stats_collector,
    ));

    let runtime = Arc::new(
        Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap(),
    );

    let agent_id = Arc::new(RwLock::new(AgentId {
        ip: Ipv4Addr::UNSPECIFIED.into(),
        mac: Default::default(),
        team_id: "example-team".to_owned(),
    }));

    let executor = Executor::new(agent_id, session, runtime);
    executor.start();

    loop {}
}
