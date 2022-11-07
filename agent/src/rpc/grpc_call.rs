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
    sync::{atomic::Ordering, Arc},
    time::Instant,
};

use async_trait::async_trait;
use log::debug;
use tonic::transport::Channel;

use crate::proto::trident::{self, synchronizer_client::SynchronizerClient};
use crate::utils::time::AtomicTimeStats;

use public::counter::{Counter, CounterType, CounterValue, RefCountable};

#[derive(Default)]
pub struct GrpcCallCounter {
    pub delay: AtomicTimeStats,
}

impl RefCountable for GrpcCallCounter {
    fn get_counters(&self) -> Vec<Counter> {
        vec![
            (
                "max_delay",
                CounterType::Gauged,
                CounterValue::Unsigned(self.delay.max.as_millis() as u64),
            ),
            (
                "avg_delay",
                CounterType::Gauged,
                CounterValue::Unsigned(
                    (self.delay.sum.as_millis() / self.delay.count.load(Ordering::Relaxed) as u128)
                        as u64,
                ),
            ),
        ]
    }
}

// wait feature #![feature(type_alias_impl_trait)] stable, we make below async call methods zero cost
// reference: https://rust-lang.github.io/rfcs/2515-type_alias_impl_trait.html
#[async_trait]
pub trait GrpcWrapper<Response> {
    async fn call(
        self,
        client: SynchronizerClient<Channel>,
    ) -> Result<tonic::Response<Response>, tonic::Status>;

    async fn call_with_statsd(
        self,
        client: SynchronizerClient<Channel>,
        counters: &Vec<(&'static str, Arc<GrpcCallCounter>)>,
    ) -> Result<tonic::Response<Response>, tonic::Status>;
}

#[async_trait]
impl GrpcWrapper<tonic::codec::Streaming<trident::SyncResponse>> for trident::SyncRequest {
    async fn call(
        self,
        mut client: SynchronizerClient<Channel>,
    ) -> Result<tonic::Response<tonic::codec::Streaming<trident::SyncResponse>>, tonic::Status>
    {
        client.push(self).await
    }

    async fn call_with_statsd(
        self,
        client: SynchronizerClient<Channel>,
        counters: &Vec<(&'static str, Arc<GrpcCallCounter>)>,
    ) -> Result<tonic::Response<tonic::codec::Streaming<trident::SyncResponse>>, tonic::Status>
    {
        let now = Instant::now();
        let response = self.call(client).await;
        let now_elapsed = now.elapsed();
        if let Some((_, counter)) = counters.iter().find(|(p, _)| *p == "push") {
            counter.delay.update(now_elapsed);
        } else {
            debug!("grpc <push> call don't exist in GrpcCallCounter list");
        }

        response
    }
}

#[async_trait]
impl GrpcWrapper<trident::SyncResponse> for trident::SyncRequest {
    async fn call(
        self,
        mut client: SynchronizerClient<Channel>,
    ) -> Result<tonic::Response<trident::SyncResponse>, tonic::Status> {
        client.sync(self).await
    }

    async fn call_with_statsd(
        self,
        client: SynchronizerClient<Channel>,
        counters: &Vec<(&'static str, Arc<GrpcCallCounter>)>,
    ) -> Result<tonic::Response<trident::SyncResponse>, tonic::Status> {
        let now = Instant::now();
        let response = self.call(client).await;
        let now_elapsed = now.elapsed();
        if let Some((_, counter)) = counters.iter().find(|(p, _)| *p == "sync") {
            counter.delay.update(now_elapsed);
        } else {
            debug!("grpc <sync> call don't exist in GrpcCallCounter list");
        }
        response
    }
}

#[async_trait]
impl GrpcWrapper<tonic::codec::Streaming<trident::UpgradeResponse>> for trident::UpgradeRequest {
    async fn call(
        self,
        mut client: SynchronizerClient<Channel>,
    ) -> Result<tonic::Response<tonic::codec::Streaming<trident::UpgradeResponse>>, tonic::Status>
    {
        client.upgrade(self).await
    }

    async fn call_with_statsd(
        self,
        client: SynchronizerClient<Channel>,
        counters: &Vec<(&'static str, Arc<GrpcCallCounter>)>,
    ) -> Result<tonic::Response<tonic::codec::Streaming<trident::UpgradeResponse>>, tonic::Status>
    {
        let now = Instant::now();
        let response = self.call(client).await;
        let now_elapsed = now.elapsed();
        if let Some((_, counter)) = counters.iter().find(|(p, _)| *p == "upgrade") {
            counter.delay.update(now_elapsed);
        } else {
            debug!("grpc <upgrade> call don't exist in GrpcCallCounter list");
        }
        response
    }
}

#[async_trait]
impl GrpcWrapper<trident::NtpResponse> for trident::NtpRequest {
    async fn call(
        self,
        mut client: SynchronizerClient<Channel>,
    ) -> Result<tonic::Response<trident::NtpResponse>, tonic::Status> {
        client.query(self).await
    }

    async fn call_with_statsd(
        self,
        client: SynchronizerClient<Channel>,
        counters: &Vec<(&'static str, Arc<GrpcCallCounter>)>,
    ) -> Result<tonic::Response<trident::NtpResponse>, tonic::Status> {
        let now = Instant::now();
        let response = self.call(client).await;
        let now_elapsed = now.elapsed();
        if let Some((_, counter)) = counters.iter().find(|(p, _)| *p == "query") {
            counter.delay.update(now_elapsed);
        } else {
            debug!("grpc <query> call don't exist in GrpcCallCounter list");
        }
        response
    }
}

#[async_trait]
impl GrpcWrapper<trident::GenesisSyncResponse> for trident::GenesisSyncRequest {
    async fn call(
        self,
        mut client: SynchronizerClient<Channel>,
    ) -> Result<tonic::Response<trident::GenesisSyncResponse>, tonic::Status> {
        client.genesis_sync(self).await
    }

    async fn call_with_statsd(
        self,
        client: SynchronizerClient<Channel>,
        counters: &Vec<(&'static str, Arc<GrpcCallCounter>)>,
    ) -> Result<tonic::Response<trident::GenesisSyncResponse>, tonic::Status> {
        let now = Instant::now();
        let response = self.call(client).await;
        let now_elapsed = now.elapsed();
        if let Some((_, counter)) = counters.iter().find(|(p, _)| *p == "genesis_sync") {
            counter.delay.update(now_elapsed);
        } else {
            debug!("grpc <genesis_sync> call don't exist in GrpcCallCounter list");
        }
        response
    }
}

#[async_trait]
impl GrpcWrapper<trident::KubernetesApiSyncResponse> for trident::KubernetesApiSyncRequest {
    async fn call(
        self,
        mut client: SynchronizerClient<Channel>,
    ) -> Result<tonic::Response<trident::KubernetesApiSyncResponse>, tonic::Status> {
        client.kubernetes_api_sync(self).await
    }

    async fn call_with_statsd(
        self,
        client: SynchronizerClient<Channel>,
        counters: &Vec<(&'static str, Arc<GrpcCallCounter>)>,
    ) -> Result<tonic::Response<trident::KubernetesApiSyncResponse>, tonic::Status> {
        let now = Instant::now();
        let response = self.call(client).await;
        let now_elapsed = now.elapsed();
        if let Some((_, counter)) = counters.iter().find(|(p, _)| *p == "kubernetes_api_sync") {
            counter.delay.update(now_elapsed);
        } else {
            debug!("grpc <kubernetes_api_sync> call don't exist in GrpcCallCounter list");
        }
        response
    }
}

#[async_trait]
impl GrpcWrapper<trident::KubernetesClusterIdResponse> for trident::KubernetesClusterIdRequest {
    async fn call(
        self,
        mut client: SynchronizerClient<Channel>,
    ) -> Result<tonic::Response<trident::KubernetesClusterIdResponse>, tonic::Status> {
        client.get_kubernetes_cluster_id(self).await
    }

    async fn call_with_statsd(
        self,
        client: SynchronizerClient<Channel>,
        counters: &Vec<(&'static str, Arc<GrpcCallCounter>)>,
    ) -> Result<tonic::Response<trident::KubernetesClusterIdResponse>, tonic::Status> {
        let now = Instant::now();
        let response = self.call(client).await;
        let now_elapsed = now.elapsed();
        if let Some((_, counter)) = counters
            .iter()
            .find(|(p, _)| *p == "get_kubernetes_cluster_id")
        {
            counter.delay.update(now_elapsed);
        } else {
            debug!("grpc <get_kubernetes_cluster_id> call don't exist in GrpcCallCounter list");
        }
        response
    }
}
