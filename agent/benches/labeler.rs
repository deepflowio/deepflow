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

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use criterion::*;
use ipnet::IpNet;

use deepflow_agent::_Acl as Acl;
use deepflow_agent::_Cidr as Cidr;
use deepflow_agent::_DirectionType as DirectionType;
use deepflow_agent::_EndpointData as EndpointData;
use deepflow_agent::_EndpointInfo as EndpointInfo;
use deepflow_agent::_FeatureFlags as FeatureFlags;
use deepflow_agent::_FirstPath as FirstPath;
use deepflow_agent::_IpGroupData as IpGroupData;
use deepflow_agent::_Labeler as Labeler;
use deepflow_agent::_LookupKey as LookupKey;
use deepflow_agent::_NpbAction as NpbAction;
use deepflow_agent::_NpbTunnelType as NpbTunnelType;
use deepflow_agent::_PortRange as PortRange;
use deepflow_agent::_TapSide as TapSide;
use deepflow_agent::{_IpSubnet as IpSubnet, _PlatformData as PlatformData};
use public::utils::net::MacAddr;

fn bench_labeler(c: &mut Criterion) {
    c.bench_function("labeler", |b| {
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

        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                labeler.get_endpoint_data(&key);
            }
            start.elapsed()
        })
    });
}

fn bench_policy(c: &mut Criterion) {
    fn generate_table() -> FirstPath {
        let mut first = FirstPath::new(1, 8, 1 << 16, false);
        let acl = Acl::new(
            1,
            vec![10],
            vec![20],
            vec![PortRange::new(80, 80)],
            vec![PortRange::new(100, 100)],
            NpbAction::new(
                0,
                100,
                "192.168.1.100".parse::<IpAddr>().unwrap(),
                1,
                NpbTunnelType::VxLan,
                TapSide::SRC,
                DirectionType::FORWARD,
                0,
            ),
        );

        first.update_ip_group(&vec![
            Arc::new(IpGroupData::new(10, 2, "192.168.2.1/32")),
            Arc::new(IpGroupData::new(20, 20, "192.168.2.5/31")),
        ]);
        let _ = first.update_acl(&vec![Arc::new(acl)], true);

        first
    }

    c.bench_function("first", |b| {
        let mut first = generate_table();
        let mut key = LookupKey {
            src_ip: "192.168.2.1".parse::<IpAddr>().unwrap(),
            dst_ip: "192.168.2.5".parse::<IpAddr>().unwrap(),
            src_port: 80,
            dst_port: 100,
            ..Default::default()
        };
        let endpoints = EndpointData {
            src_info: EndpointInfo {
                l3_epc_id: 2,
                ..Default::default()
            },
            dst_info: EndpointInfo {
                l3_epc_id: 20,
                ..Default::default()
            },
        };

        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                first.first_get(&mut key, endpoints);
            }
            start.elapsed()
        })
    });

    c.bench_function("fast", |b| {
        let mut first = generate_table();
        let mut key = LookupKey {
            src_ip: "192.168.2.1".parse::<IpAddr>().unwrap(),
            dst_ip: "192.168.2.5".parse::<IpAddr>().unwrap(),
            src_port: 80,
            dst_port: 100,
            feature_flag: FeatureFlags::NONE,
            ..Default::default()
        };

        let endpoints = EndpointData {
            src_info: EndpointInfo {
                l3_epc_id: 2,
                ..Default::default()
            },
            dst_info: EndpointInfo {
                l3_epc_id: 20,
                ..Default::default()
            },
        };

        first.first_get(&mut key, endpoints);
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                first.fast_get(&mut key);
            }
            start.elapsed()
        })
    });
}

criterion_group!(benches, bench_labeler, bench_policy);
criterion_main!(benches);
