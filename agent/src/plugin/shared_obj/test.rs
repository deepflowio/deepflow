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
    cell::RefCell,
    fs,
    io::Read,
    net::{IpAddr, Ipv4Addr},
    rc::Rc,
    time::Duration,
};

use public::enums::IpProtocol;

use crate::{
    common::{
        ebpf::EbpfType,
        l7_protocol_info::L7ProtocolInfo,
        l7_protocol_log::{EbpfParam, L7PerfCache, ParseParam},
    },
    flow_generator::protocol_logs::plugin::shared_obj::get_so_parser,
};
use crate::{
    common::{flow::PacketDirection, l7_protocol_log::L7ProtocolParserInterface},
    flow_generator::protocol_logs::plugin::shared_obj::SoLog,
};
use crate::{
    config::OracleParseConfig,
    flow_generator::protocol_logs::{pb_adapter::KeyVal, L7ResponseStatus, LogMessageType},
};

use super::{load_plugin, SoPluginFunc};

fn get_plugin() -> SoPluginFunc {
    // the so source code lcoate in resources/test/plugins/so_plugin_test.c
    let mut f = fs::File::open("resources/test/plugins/so_plugin_test").unwrap();
    let mut b = vec![];
    f.read_to_end(&mut b).unwrap();

    load_plugin(b.as_slice(), &"test".into()).unwrap()
}

fn get_req_param<'a>(
    rrt_cache: Rc<RefCell<L7PerfCache>>,
    plugin: Rc<RefCell<Option<Vec<SoPluginFunc>>>>,
) -> ParseParam<'a> {
    ParseParam {
        l4_protocol: IpProtocol::TCP,
        ip_src: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        ip_dst: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        port_src: 12345,
        port_dst: 8080,
        flow_id: 1234567,
        direction: PacketDirection::ClientToServer,
        ebpf_type: EbpfType::TracePoint,
        ebpf_param: Some(EbpfParam {
            is_tls: false,
            is_req_end: false,
            is_resp_end: false,
            process_kname: "test_wasm",
        }),
        packet_seq: 9999999,
        time: 12345678,
        parse_log: true,
        parse_perf: true,
        parse_config: None,
        l7_perf_cache: rrt_cache.clone(),
        wasm_vm: Default::default(),
        so_func: plugin,
        stats_counter: None,
        rrt_timeout: Duration::from_secs(10).as_micros() as usize,
        buf_size: 0,
        captured_byte: 0,
        oracle_parse_conf: OracleParseConfig::default(),
    }
}

fn get_resp_param<'a>(
    rrt_cache: Rc<RefCell<L7PerfCache>>,
    plugin: Rc<RefCell<Option<Vec<SoPluginFunc>>>>,
) -> ParseParam<'a> {
    ParseParam {
        l4_protocol: IpProtocol::TCP,
        ip_src: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        ip_dst: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        port_src: 8080,
        port_dst: 12345,
        flow_id: 1234567,
        direction: PacketDirection::ServerToClient,
        ebpf_type: EbpfType::TracePoint,

        ebpf_param: Some(EbpfParam {
            is_tls: false,
            is_req_end: false,
            is_resp_end: false,
            process_kname: "test_wasm",
        }),
        packet_seq: 9999999,
        time: 12345679,
        parse_perf: true,
        parse_log: true,
        parse_config: None,
        l7_perf_cache: rrt_cache.clone(),
        wasm_vm: Default::default(),
        so_func: plugin,
        stats_counter: None,
        rrt_timeout: Duration::from_secs(10).as_micros() as usize,
        buf_size: 0,
        captured_byte: 0,
        oracle_parse_conf: OracleParseConfig::default(),
    }
}

static REQ_PAYLOAD: [u8; 50] = [
    58, 166, 1, 32, 0, 1, 0, 0, 0, 0, 0, 1, 5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0, 0, 1, 0,
    1, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 115, 109, 120, 32, 132, 36, 153, 244,
];

static RESP_PAYLOAD: [u8; 70] = [
    58, 166, 129, 128, 0, 1, 0, 2, 0, 0, 0, 1, 5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0, 0, 1,
    0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 0, 128, 0, 4, 39, 156, 66, 10, 192, 12, 0, 1, 0, 1, 0, 0, 0,
    128, 0, 4, 110, 242, 68, 66, 0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 0,
];

#[test]
fn test_check() {
    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
    let param = get_req_param(rrt_cache, Rc::new(RefCell::new(Some(vec![get_plugin()]))));
    let mut p = SoLog::default();
    assert!(p.check_payload(&REQ_PAYLOAD, &param));
}

#[test]
fn test_parse() {
    let attr = vec![
        KeyVal {
            key: "key1".into(),
            val: "val1".into(),
        },
        KeyVal {
            key: "key2".into(),
            val: "val2".into(),
        },
    ];
    let plugin = Rc::new(RefCell::new(Some(vec![get_plugin()])));

    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
    let param = get_req_param(rrt_cache.clone(), plugin.clone());
    let mut p = get_so_parser(1, "dns".into());
    let infos = p.parse_payload(&REQ_PAYLOAD, &param).unwrap();
    let info = infos.unwrap_single();

    if let L7ProtocolInfo::CustomInfo(info) = info {
        assert_eq!(info.proto, 1);
        assert_eq!(info.proto_str.as_str(), "dns");
        assert_eq!(info.msg_type, LogMessageType::Request);
        assert_eq!(info.request_id.unwrap(), 15014);

        assert_eq!(info.req.req_type, "A");
        assert_eq!(info.req.domain.as_str(), "baidu.com.");

        assert_eq!(
            info.trace.trace_id.as_ref().unwrap().as_str(),
            "this is trace id"
        );
        assert_eq!(
            info.trace.span_id.as_ref().unwrap().as_str(),
            "this is span id"
        );
        assert_eq!(
            info.trace.parent_span_id.as_ref().unwrap().as_str(),
            "this is parent span id"
        );

        assert_eq!(info.attributes, attr);
    } else {
        unreachable!()
    }

    let param = get_resp_param(rrt_cache, plugin.clone());
    let infos = p.parse_payload(&RESP_PAYLOAD, &param).unwrap();
    let info = infos.unwrap_single();

    if let L7ProtocolInfo::CustomInfo(info) = info {
        assert_eq!(info.proto, 1);
        assert_eq!(info.proto_str.as_str(), "dns");
        assert_eq!(info.msg_type, LogMessageType::Response);
        assert_eq!(info.request_id.unwrap(), 15014);

        assert!(info.resp.exception.is_empty());
        assert_eq!(info.resp.code.unwrap(), 0);
        assert_eq!(info.resp.result.as_str(), "110.242.68.66");
        assert_eq!(info.resp.status, L7ResponseStatus::Ok);

        assert_eq!(
            info.trace.trace_id.as_ref().unwrap().as_str(),
            "this is trace id"
        );
        assert_eq!(
            info.trace.span_id.as_ref().unwrap().as_str(),
            "this is span id"
        );
        assert_eq!(
            info.trace.parent_span_id.as_ref().unwrap().as_str(),
            "this is parent span id"
        );

        assert_eq!(info.attributes, attr);
    } else {
        unreachable!()
    }

    let stat = p.perf_stats().unwrap();
    assert_eq!(stat.request_count, 1);
    assert_eq!(stat.response_count, 1);
    assert_eq!(stat.rrt_count, 1);
    assert_eq!(stat.rrt_max, 1);
    assert_eq!(stat.rrt_sum, 1);
}
