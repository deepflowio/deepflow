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

use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use criterion::*;
use ipnet::IpNet;

use deepflow_agent::_Cidr as Cidr;
use deepflow_agent::_Labeler as Labeler;
use deepflow_agent::_LookupKey as LookupKey;
use deepflow_agent::_MacAddr as MacAddr;
use deepflow_agent::{_IpSubnet as IpSubnet, _PlatformData as PlatformData};

fn bench_labeler(c: &mut Criterion) {
    c.bench_function("labeler", |b| {
        b.iter_custom(|iters| {
            let mut labeler: Labeler = Default::default();
            let mut cidr_list: Vec<Arc<Cidr>> = Vec::new();
            let mut iface_list: Vec<Arc<PlatformData>> = Vec::new();
            let interface: PlatformData = PlatformData {
                mac: 0x112233445566,
                ips: vec![IpSubnet {
                    raw_ip: "192.168.0.200".parse().unwrap(),
                    ..Default::default()
                }],
                epc_id: 10,
                ..Default::default()
            };
            iface_list.push(Arc::new(interface));

            for i in 0..100 {
                let ip = "192.168.".to_string().as_str().to_owned()
                    + ((i >> 8) & 0xff).to_string().as_str()
                    + ".".to_string().as_str()
                    + (i & 0xff).to_string().as_str()
                    + "/32".to_string().as_str();
                let cidr: Cidr = Cidr {
                    ip: IpNet::from_str(&ip).unwrap(),
                    epc_id: 10,
                    ..Default::default()
                };

                cidr_list.push(Arc::new(cidr));
            }
            labeler.update_cidr_table(&cidr_list);
            labeler.update_interface_table(&iface_list);

            let key: LookupKey = LookupKey {
                src_mac: MacAddr::from_str("11:22:33:44:55:66").unwrap(),
                src_ip: "192.168.0.100".parse().unwrap(),
                dst_ip: "192.168.0.200".parse().unwrap(),
                ..Default::default()
            };

            let start = Instant::now();
            for _ in 0..iters {
                labeler.get_endpoint_data(&key);
            }
            start.elapsed()
        })
    });
}

criterion_group!(benches, bench_labeler);
criterion_main!(benches);
