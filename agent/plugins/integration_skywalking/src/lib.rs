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

use hyper::{Body, Response, StatusCode};
use prost::EncodeError;
use public::{
    proto::flow_log,
    queue::DebugSender,
    sender::{SendMessageType, Sendable},
};
use std::net::SocketAddr;

#[derive(Debug, PartialEq)]
pub struct SkyWalkingExtra(pub flow_log::ThirdPartyTrace);

impl Sendable for SkyWalkingExtra {
    fn encode(self, _: &mut Vec<u8>) -> Result<usize, EncodeError> {
        return Ok(0);
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::SkyWalking
    }
}

pub async fn handle_skywalking_request(
    _: SocketAddr,
    _: Vec<u8>,
    _: &str,
    _: DebugSender<SkyWalkingExtra>,
) -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .unwrap()
}

pub async fn handle_skywalking_streaming_request(
    _: SocketAddr,
    _: Body,
    _: &str,
    _: DebugSender<SkyWalkingExtra>,
) -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .unwrap()
}
