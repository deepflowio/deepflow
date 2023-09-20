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

use std::io;
use std::net::ToSocketAddrs;

use tonic::transport::{Channel, Endpoint};

use public::consts::{GRPC_DEFAULT_TIMEOUT, GRPC_SESSION_TIMEOUT};

pub async fn dial(remote: &str, remote_port: u16, _: String) -> Result<Channel, String> {
    let socket_address = match (remote, remote_port)
        .to_socket_addrs()
        .and_then(|mut iter| {
            iter.next()
                .ok_or(io::Error::new(io::ErrorKind::InvalidData, "result is empty").into())
        }) {
        Ok(addr) => addr,
        Err(e) => {
            return Err(format!(
                "resolve socket address remote({}) port({}) failed: {}",
                remote, remote_port, e
            ));
        }
    };

    let endpoint = match Endpoint::from_shared(format!("http://{}", socket_address)) {
        Ok(ep) => ep,
        Err(e) => {
            return Err(format!(
                "create endpoint http://{} failed {}",
                socket_address, e
            ));
        }
    };

    match endpoint
        .connect_timeout(GRPC_DEFAULT_TIMEOUT)
        .timeout(GRPC_SESSION_TIMEOUT)
        .connect()
        .await
    {
        Ok(channel) => return Ok(channel),
        Err(e) => {
            return Err(format!(
                "Dial server({} {}) failed: {}",
                remote, remote_port, e
            ));
        }
    }
}
