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

use core::panic;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::time::Duration;

use flate2::read::GzDecoder;
use public::enums::IpProtocol;
use public::l7_protocol::CustomProtocol;

use crate::common::ebpf::EbpfType;
use crate::common::flow::PacketDirection;
use crate::common::l7_protocol_info::L7ProtocolInfo;
use crate::common::l7_protocol_log::{EbpfParam, L7PerfCache};

use crate::config::handler::LogParserConfig;
use crate::config::OracleParseConfig;
use crate::flow_generator::protocol_logs::pb_adapter::L7ProtocolSendLog;
use crate::flow_generator::protocol_logs::{get_wasm_parser, L7ResponseStatus, WasmLog};
use crate::{
    common::l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    HttpLog,
};

use super::WasmVm;

fn get_req_param<'a>(
    vm: Rc<RefCell<WasmVm>>,
    rrt_cache: Rc<RefCell<L7PerfCache>>,
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
            process_kname: "test_wasm".to_string(),
        }),
        packet_seq: 9999999,
        time: 12345678,
        parse_perf: true,
        parse_log: true,
        parse_config: None,
        l7_perf_cache: rrt_cache.clone(),
        wasm_vm: Some(vm.clone()),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        so_func: None,
        stats_counter: None,
        rrt_timeout: Duration::from_secs(10).as_micros() as usize,
        buf_size: 999,
        oracle_parse_conf: OracleParseConfig::default(),
    }
}

fn get_resq_param<'a>(
    vm: Rc<RefCell<WasmVm>>,
    rrt_cache: Rc<RefCell<L7PerfCache>>,
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
            process_kname: "test_wasm".to_string(),
        }),
        packet_seq: 9999999,
        time: 12345678,
        parse_perf: true,
        parse_log: true,
        parse_config: None,
        l7_perf_cache: rrt_cache.clone(),
        wasm_vm: Some(vm.clone()),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        so_func: None,
        stats_counter: None,
        rrt_timeout: Duration::from_secs(10).as_micros() as usize,
        buf_size: 999,
        oracle_parse_conf: OracleParseConfig::default(),
    }
}

fn load_module() -> WasmVm {
    let mut f = File::open("resources/test/plugins/wasm_test.wasm.gz").unwrap();
    let mut gz_prog = vec![];
    f.read_to_end(&mut gz_prog).unwrap();

    let mut d = GzDecoder::new(gz_prog.as_slice());
    let mut prog = vec![];
    d.read_to_end(&mut prog).unwrap();

    WasmVm::new(&[("vm0", prog)])
}

#[test]
fn test_wasm_http_req() {
    let vm = Rc::new(RefCell::new(load_module()));
    let config = LogParserConfig::default();
    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

    let mut param = get_req_param(vm.clone(), rrt_cache.clone());
    param.parse_config = Some(&config);

    let mut http = HttpLog::new_v1();
    let payload = "POST /test?a=1&b=2&c=test HTTP/1.1\r\nUser-Agent: deepflow\r\nreferer: aaa.com\r\nHost: abc.com\r\nContent-Type: application/json\r\n\r\n";
    let info = http.parse_payload(payload.as_bytes(), &param).unwrap();

    let kv: HashMap<&str, &str> =
        HashMap::from_iter([("a", "1"), ("b", "2"), ("c", "test"), ("empty", "")]);

    if let L7ProtocolInfo::HttpInfo(http) = info.unwrap_single() {
        let i: L7ProtocolSendLog = http.into();
        assert_eq!(
            i.trace_info
                .as_ref()
                .unwrap()
                .trace_id
                .as_ref()
                .unwrap()
                .as_str(),
            "aaa"
        );
        assert_eq!(
            i.trace_info
                .as_ref()
                .unwrap()
                .span_id
                .as_ref()
                .unwrap()
                .as_str(),
            "bbb"
        );

        assert_eq!(i.req.domain.as_str(), "rewrite domain");
        assert_eq!(i.req.req_type.as_str(), "rewrite req type");
        assert_eq!(i.req.resource.as_str(), "rewrite resource");
        assert_eq!(i.req.endpoint.as_str(), "rewrite endpoint");

        let attr = i.ext_info.unwrap().attributes.unwrap();

        assert_eq!(attr.len(), kv.len());
        for i in attr {
            if kv.contains_key(i.key.as_str()) {
                let val = kv.get(i.key.as_str()).unwrap();
                if !(*val).eq(i.val.as_str()) {
                    panic!("key:{} val not eq, {}:{}", i.key, i.val, val);
                }
            }
        }
    } else {
        unreachable!()
    };
}

#[test]
fn test_wasm_http_resp() {
    let vm = Rc::new(RefCell::new(load_module()));
    let config = LogParserConfig::default();
    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

    let mut param = get_resq_param(vm.clone(), rrt_cache.clone());
    param.parse_config = Some(&config);

    let mut http = HttpLog::new_v1();
    let payload = "HTTP/1.1 200 Ok\r\nContent-Type: application/json\r\n\r\n{\"data\":{\"user_id\":123, \"name\":\"kkk\"}}";
    let info = http.parse_payload(payload.as_bytes(), &param).unwrap();

    let kv: HashMap<&str, &str> = HashMap::from_iter([("user_id", "123"), ("username", "kkk")]);

    if let L7ProtocolInfo::HttpInfo(http) = info.unwrap_single() {
        let i: L7ProtocolSendLog = http.into();
        assert_eq!(
            i.trace_info
                .as_ref()
                .unwrap()
                .trace_id
                .as_ref()
                .unwrap()
                .as_str(),
            ""
        );
        assert_eq!(
            i.trace_info
                .as_ref()
                .unwrap()
                .span_id
                .as_ref()
                .unwrap()
                .as_str(),
            ""
        );

        assert_eq!(i.resp.code.unwrap(), 599);
        assert_eq!(i.resp.status, L7ResponseStatus::ServerError);
        assert_eq!(i.resp.exception.as_str(), "rewrite exception");
        assert_eq!(i.resp.result, "rewrite result");

        let attr = i.ext_info.unwrap().attributes.unwrap();
        assert_eq!(attr.len(), kv.len());
        for i in attr {
            if kv.contains_key(i.key.as_str()) {
                let val = kv.get(i.key.as_str()).unwrap();
                if !(*val).eq(i.val.as_str()) {
                    panic!("key:{} val not eq, {}:{}", i.key, i.val, val);
                }
            }
        }
    } else {
        unreachable!()
    };
}

#[test]
fn test_check_payload() {
    let vm = Rc::new(RefCell::new(load_module()));
    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

    let param = get_req_param(vm.clone(), rrt_cache.clone());

    let mut wasm_log = WasmLog::default();
    let payload: [u8; 34] = [
        10, 6, 100, 111, 109, 97, 105, 110, 18, 8, 114, 101, 115, 111, 117, 114, 99, 101, 26, 4,
        116, 121, 112, 101, 34, 8, 101, 110, 100, 112, 111, 105, 110, 116,
    ];
    assert_eq!(wasm_log.check_payload(&payload[..], &param), true);
    assert_eq!(
        wasm_log.custom_protocol().unwrap(),
        CustomProtocol::Wasm(1, "test".to_string())
    );
}

#[test]
fn test_wasm_parse_payload_req() {
    let vm = Rc::new(RefCell::new(load_module()));

    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

    let param = get_req_param(vm.clone(), rrt_cache.clone());

    let mut wasm_log = get_wasm_parser(1, "".to_string());
    let payload: [u8; 34] = [
        10, 6, 100, 111, 109, 97, 105, 110, 18, 8, 114, 101, 115, 111, 117, 114, 99, 101, 26, 4,
        116, 121, 112, 101, 34, 8, 101, 110, 100, 112, 111, 105, 110, 116,
    ];
    let info1 = wasm_log
        .parse_payload(&payload[..], &param)
        .unwrap()
        .unwrap_multi()
        .remove(0);
    if let L7ProtocolInfo::CustomInfo(ci) = info1 {
        assert_eq!(ci.req_len.unwrap(), 999);
        assert_eq!(ci.resp_len.unwrap(), 9999);
        assert_eq!(ci.request_id.unwrap(), 666);
        assert_eq!(ci.req.domain.as_str(), "domain");
        assert_eq!(ci.req.req_type.as_str(), "type");
        assert_eq!(ci.req.resource.as_str(), "resource");
        assert_eq!(ci.req.endpoint.as_str(), "endpoint");

        assert_eq!(ci.trace.trace_id.unwrap(), "11111");
        assert_eq!(ci.trace.span_id.unwrap(), "22222");
        assert_eq!(ci.trace.parent_span_id.unwrap(), "33333");

        let attr1 = ci.attributes.get(0).unwrap();
        let attr2 = ci.attributes.get(1).unwrap();
        assert_eq!(attr1.key.as_str(), "k1");
        assert_eq!(attr1.val.as_str(), "");

        assert_eq!(attr2.key.as_str(), "k2");
        assert_eq!(attr2.val.as_str(), "v2");

        assert_eq!(ci.need_protocol_merge, true);
        assert_eq!(ci.is_req_end, true);
    } else {
        unreachable!()
    }

    let info2 = wasm_log
        .parse_payload(&payload[..], &param)
        .unwrap()
        .unwrap_multi()
        .remove(1);

    if let L7ProtocolInfo::CustomInfo(ci) = info2 {
        assert_eq!(ci.req_len.unwrap(), 999);
        assert_eq!(ci.resp_len.unwrap(), 9999);
        assert_eq!(ci.request_id.unwrap(), 666);
        assert_eq!(ci.req.domain.as_str(), "domain");
        assert_eq!(ci.req.req_type.as_str(), "type");
        assert_eq!(ci.req.resource.as_str(), "resource");
        assert_eq!(ci.req.endpoint.as_str(), "endpoint");

        assert_eq!(ci.trace.trace_id.unwrap(), "11111");
        assert_eq!(ci.trace.span_id.unwrap(), "22222");
        assert_eq!(ci.trace.parent_span_id.unwrap(), "33333");

        let attr1 = ci.attributes.get(0).unwrap();
        let attr2 = ci.attributes.get(1).unwrap();
        assert_eq!(attr1.key.as_str(), "k3");
        assert_eq!(attr1.val.as_str(), "v3");

        assert_eq!(attr2.key.as_str(), "k4");
        assert_eq!(attr2.val.as_str(), "v4");

        assert_eq!(ci.need_protocol_merge, true);
        assert_eq!(ci.is_req_end, true);
    } else {
        unreachable!()
    }
}

#[test]
fn test_wasm_parse_payload_resp() {
    let vm = Rc::new(RefCell::new(load_module()));
    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

    let param = get_resq_param(vm.clone(), rrt_cache.clone());

    let mut wasm_log = get_wasm_parser(1, "".to_string());
    let payload: [u8; 11] = [8, 231, 7, 18, 6, 114, 101, 115, 117, 108, 116];
    let info1 = wasm_log
        .parse_payload(&payload[..], &param)
        .unwrap()
        .unwrap_multi()
        .remove(0);
    if let L7ProtocolInfo::CustomInfo(ci) = info1 {
        assert_eq!(ci.req_len.unwrap(), 999);
        assert_eq!(ci.resp_len.unwrap(), 9999);
        assert_eq!(ci.request_id.unwrap(), 666);
        assert_eq!(ci.resp.status, L7ResponseStatus::Ok);
        assert_eq!(ci.resp.code.unwrap(), 999);
        assert_eq!(ci.resp.result, "result");
        assert_eq!(ci.resp.exception, "exception");

        assert_eq!(ci.trace.trace_id.unwrap(), "11111");
        assert_eq!(ci.trace.span_id.unwrap(), "22222");
        assert_eq!(ci.trace.parent_span_id.unwrap(), "33333");

        let attr1 = ci.attributes.get(0).unwrap();
        let attr2 = ci.attributes.get(1).unwrap();
        assert_eq!(attr1.key.as_str(), "k1");
        assert_eq!(attr1.val.as_str(), "v1");

        assert_eq!(attr2.key.as_str(), "k2");
        assert_eq!(attr2.val.as_str(), "v2");
    } else {
        unreachable!()
    }

    let info2 = wasm_log
        .parse_payload(&payload[..], &param)
        .unwrap()
        .unwrap_multi()
        .remove(1);
    if let L7ProtocolInfo::CustomInfo(ci) = info2 {
        assert_eq!(ci.req_len.unwrap(), 999);
        assert_eq!(ci.resp_len.unwrap(), 9999);
        assert_eq!(ci.request_id.unwrap(), 666);
        assert_eq!(ci.resp.status, L7ResponseStatus::Ok);
        assert_eq!(ci.resp.code.unwrap(), 999);
        assert_eq!(ci.resp.result, "result");
        assert_eq!(ci.resp.exception, "exception");

        assert_eq!(ci.trace.trace_id.unwrap(), "11111");
        assert_eq!(ci.trace.span_id.unwrap(), "22222");
        assert_eq!(ci.trace.parent_span_id.unwrap(), "33333");

        let attr1 = ci.attributes.get(0).unwrap();
        let attr2 = ci.attributes.get(1).unwrap();
        assert_eq!(attr1.key.as_str(), "k3");
        assert_eq!(attr1.val.as_str(), "");

        assert_eq!(attr2.key.as_str(), "k4");
        assert_eq!(attr2.val.as_str(), "v4");
    } else {
        unreachable!()
    }
}

// the protobuf message use in test, it use the go plugin gen the go code: ​https://github.com/knqyf263/go-plugin
// compile commnad: protoc --go-plugin_out=. --go-plugin_opt=paths=source_relative proto.proto

/*
syntax = "proto3";
package proto;

option go_package = "./pb";


message Req {
  string domain = 1;
  string resource = 2;
  string type = 3;
  string endpoint = 4;
}


message Resp {
  uint32 status = 1;
  string result = 2;
}
*/

// go wasm code, build cocmmand:
// tinygo  build -o wasm.wasm  -target wasi -wasm-abi=generic -panic trap -scheduler=none -no-debug ./main.go

/*
package main

import (
    "bufio"
    "bytes"
    "encoding/base64"
    "github.com/deepflowio/deepflow-wasm-go-sdk/pb"
    "github.com/deepflowio/deepflow-wasm-go-sdk/sdk"
    "github.com/valyala/fastjson"
    "io"
    "net/http"
    "net/url"
    "strconv"
)

func checkReqCtx(baseCtx *sdk.ParseCtx) {
    payload, _ := baseCtx.GetPayload()
    sdk.Error("saddr %v: %v", baseCtx.SrcIP.IP, baseCtx.SrcPort)
    sdk.Error("daddr %v: %v", baseCtx.DstIP.IP, baseCtx.DstPort)
    sdk.Error("l4: %v", baseCtx.L4)
    sdk.Error("l7: %v", baseCtx.L7)
    sdk.Error("dir: %v", baseCtx.Direction)
    sdk.Error("ebpf type: %v", baseCtx.EbpfType)
    sdk.Error("proc name: %v", baseCtx.ProcName)
    sdk.Error("time: %v", baseCtx.Time)
    sdk.Error("flowid: %v", baseCtx.FlowID)
    sdk.Error("buf_size: %v", baseCtx.BufSize)
    sdk.Error("payload: %v ", payload)

    checkEq("1.2.3.4", baseCtx.SrcIP.IP.String())
    checkEq(12345, int(baseCtx.SrcPort))
    checkEq("5.6.7.8", baseCtx.DstIP.IP.String())
    checkEq(8080, int(baseCtx.DstPort))
    checkEq(sdk.TCP, baseCtx.L4)
    checkEq(sdk.DirectionRequest, baseCtx.Direction)
    checkEq(sdk.EbpfTypeTracePoint, baseCtx.EbpfType)
    checkEq("test_wasm", baseCtx.ProcName)
    checkEq(uint64(12345678), baseCtx.Time)
    checkEq(uint64(1234567), baseCtx.FlowID)
    checkEq(uint16(999), baseCtx.BufSize)
}

func checkRespCtx(baseCtx *sdk.ParseCtx) {
    payload, _ := baseCtx.GetPayload()

    sdk.Error("saddr %v: %v", baseCtx.SrcIP.IP, baseCtx.SrcPort)
    sdk.Error("daddr %v: %v", baseCtx.DstIP.IP, baseCtx.DstPort)
    sdk.Error("l4: %v", baseCtx.L4)
    sdk.Error("l7: %v", baseCtx.L7)
    sdk.Error("dir: %v", baseCtx.Direction)
    sdk.Error("ebpf type: %v", baseCtx.EbpfType)
    sdk.Error("time: %v", baseCtx.Time)
    sdk.Error("flowid: %v", baseCtx.FlowID)
    sdk.Error("buf_size: %v", baseCtx.BufSize)
    sdk.Error("p: %v ", payload)

    checkEq("5.6.7.8", baseCtx.SrcIP.IP.String())
    checkEq(uint16(8080), baseCtx.SrcPort)
    checkEq("1.2.3.4", baseCtx.DstIP.IP.String())
    checkEq(uint16(12345), baseCtx.DstPort)
    checkEq(sdk.TCP, baseCtx.L4)
    checkEq(sdk.DirectionResponse, baseCtx.Direction)
    checkEq(sdk.EbpfTypeTracePoint, baseCtx.EbpfType)
    checkEq("test_wasm", baseCtx.ProcName)
    checkEq(uint64(12345678), baseCtx.Time)
    checkEq(uint64(1234567), baseCtx.FlowID)
    checkEq(uint16(999), baseCtx.BufSize)
}

type parser struct {
}

func (p parser) HookIn() []sdk.HookBitmap {
    return []sdk.HookBitmap{
        sdk.HOOK_POINT_HTTP_REQ,
        sdk.HOOK_POINT_HTTP_RESP,
        sdk.HOOK_POINT_PAYLOAD_PARSE,
    }
}

func checkEq(a, b interface{}) {
    if a != b {
        sdk.Error("%v and %v not equal", a, b)
        panic("")
    }
}

func (p parser) OnHttpReq(ctx *sdk.HttpReqCtx) sdk.Action {
    sdk.Warn("================ enter http req ==================")
    baseCtx := &ctx.BaseCtx
    payload, err := baseCtx.GetPayload()
    if err != nil {
        sdk.Error("%v", err)
        panic(err)
    }

    checkReqCtx(baseCtx)

    sdk.Error("path: %v ", ctx.Path)
    sdk.Error("host: %v ", ctx.Host)
    sdk.Error("ua: %v ", ctx.UserAgent)
    sdk.Error("ref: %v ", ctx.Referer)

    checkEq(0, int(baseCtx.L7))
    checkEq("/test?a=1&b=2&c=test", ctx.Path)
    checkEq("abc.com", ctx.Host)
    checkEq("deepflow", ctx.UserAgent)
    checkEq("aaa.com", ctx.Referer)
    checkEq(
        "POST /test?a=1&b=2&c=test HTTP/1.1\r\nUser-Agent: deepflow\r\nreferer: aaa.com\r\nHost: abc.com\r\nContent-Type: application/json\r\n\r\n",
        string(payload),
    )

    u, err := url.Parse(ctx.Path)
    if err != nil {
        panic(err)
    }
    q := u.Query()

    attr := []sdk.KeyVal{
        {
            Key: "q",
            Val: q.Get("a"),
        },

        {
            Key: "b",
            Val: q.Get("b"),
        },
        {
            Key: "c",
            Val: q.Get("c"),
        },
        {
            Key: "empty",
            Val: "",
        },
    }

    trace := &sdk.Trace{
        TraceID:      "aaa",
        SpanID:       "bbb",
        ParentSpanID: "ccc",
    }
    return sdk.HttpReqActionAbortWithResult(&sdk.Request{
        ReqType:  "rewrite req type",
        Domain:   "rewrite domain",
        Resource: "rewrite resource",
        Endpoint: "rewrite endpoint",
    }, trace, attr)
}

func (p parser) OnHttpResp(ctx *sdk.HttpRespCtx) sdk.Action {
    sdk.Warn("================ enter http resp ==================")
    baseCtx := &ctx.BaseCtx
    payload, err := baseCtx.GetPayload()
    if err != nil {
        sdk.Error("%v", err)
        panic(err)
    }

    checkRespCtx(baseCtx)

    sdk.Error("p: %v ", string(payload))

    checkEq(0, int(baseCtx.L7))
    checkEq(uint16(200), ctx.Code)
    checkEq(sdk.RespStatusOk, ctx.Status)

    r := bufio.NewReader(bytes.NewReader(payload))
    req, err := http.ReadResponse(r, nil)
    if err != nil {
        sdk.Error("fail to parse http resp: %v", err)
        panic(err)
    }
    body, err := io.ReadAll(req.Body)
    if err != nil {
        sdk.Error("fail to read http body: %v", err)
        panic(err)
    }

    checkEq(`{"data":{"user_id":123, "name":"kkk"}}`, string(body))

    userID := fastjson.GetInt(body, "data", "user_id")
    userName := fastjson.GetString(body, "data", "name")
    var code int32 = 599
    status := sdk.RespStatusServerErr
    return sdk.HttpRespActionAbortWithResult(&sdk.Response{
        Status:    &status,
        Code:      &code,
        Result:    "rewrite result",
        Exception: "rewrite exception",
    }, nil, []sdk.KeyVal{
        {
            Key: "user_id",
            Val: strconv.Itoa(userID),
        },

        {
            Key: "username",
            Val: userName,
        },
    })
}

func (p parser) OnCheckPayload(baseCtx *sdk.ParseCtx) (uint8, string) {
    sdk.Warn("================ check payload ==================")
    checkReqCtx(baseCtx)
    payload, err := baseCtx.GetPayload()
    if err != nil {
        sdk.Error("%v", err)
        panic(err)
    }
    checkEq("CgZkb21haW4SCHJlc291cmNlGgR0eXBlIghlbmRwb2ludA==", base64.StdEncoding.EncodeToString(payload))

    a := &pb.Req{}
    if err := a.UnmarshalVT(payload); err != nil {
        sdk.Error("unmarshal pb fail: $v", err)
        panic(err)
    }

    checkEq(0, int(baseCtx.L7))
    checkEq(a.Domain, "domain")
    checkEq(a.Resource, "resource")
    checkEq(a.Type, "type")
    checkEq(a.Endpoint, "endpoint")

    return 1, "test"
}

func (p parser) OnParsePayload(baseCtx *sdk.ParseCtx) sdk.Action {
    sdk.Warn("================ parse payload ==================")
    payload, err := baseCtx.GetPayload()
    if err != nil {
        sdk.Error("%v", err)
        panic(err)
    }
    trace := &sdk.Trace{
        TraceID:      "11111",
        SpanID:       "22222",
        ParentSpanID: "33333",
    }
    switch baseCtx.Direction {
    case sdk.DirectionRequest:
        checkReqCtx(baseCtx)
        checkEq("CgZkb21haW4SCHJlc291cmNlGgR0eXBlIghlbmRwb2ludA==", base64.StdEncoding.EncodeToString(payload))
        a := &pb.Req{}
        if err := a.UnmarshalVT(payload); err != nil {
            sdk.Error("unmarshal pb fail: $v", err)
            panic(err)
        }

        checkEq(1, int(baseCtx.L7))
        checkEq(a.Domain, "domain")
        checkEq(a.Resource, "resource")
        checkEq(a.Type, "type")
        checkEq(a.Endpoint, "endpoint")
        reqLen := 999
        respLen := 9999
        requestID := uint32(666)

        return sdk.ParseActionAbortWithL7Info([]*sdk.L7ProtocolInfo{
            {
                ReqLen:    &reqLen,
                RespLen:   &respLen,
                RequestID: &requestID,
                Req: &sdk.Request{
                    ReqType:  a.Type,
                    Domain:   a.Domain,
                    Resource: a.Resource,
                    Endpoint: a.Endpoint,
                },
                Resp:  nil,
                Trace: trace,
                Kv: []sdk.KeyVal{
                    {
                        Key: "k1",
                        Val: "",
                    }, {
                        Key: "k2",
                        Val: "v2",
                    },
                },
                ProtocolMerge: true,
                IsEnd:         true,
            },
            {
                ReqLen:    &reqLen,
                RespLen:   &respLen,
                RequestID: &requestID,
                Req: &sdk.Request{
                    ReqType:  a.Type,
                    Domain:   a.Domain,
                    Resource: a.Resource,
                    Endpoint: a.Endpoint,
                },
                Resp:  nil,
                Trace: trace,
                Kv: []sdk.KeyVal{
                    {
                        Key: "k3",
                        Val: "v3",
                    }, {
                        Key: "k4",
                        Val: "v4",
                    },
                },
                ProtocolMerge: true,
                IsEnd:         true,
            },
        })

    case sdk.DirectionResponse:
        checkRespCtx(baseCtx)
        checkEq("COcHEgZyZXN1bHQ=", base64.StdEncoding.EncodeToString(payload))
        a := &pb.Resp{}
        if err := a.UnmarshalVT(payload); err != nil {
            sdk.Error("unmarshal pb fail: $v", err)
            panic(err)
        }
        checkEq(a.Result, "result")
        checkEq(a.Status, uint32(999))

        reqLen := 999
        respLen := 9999
        requestID := uint32(666)
        code := int32(999)
        status := sdk.RespStatusOk
        return sdk.ParseActionAbortWithL7Info([]*sdk.L7ProtocolInfo{
            {
                ReqLen:    &reqLen,
                RespLen:   &respLen,
                RequestID: &requestID,
                Req:       nil,
                Resp: &sdk.Response{
                    Status:    &status,
                    Code:      &code,
                    Result:    "result",
                    Exception: "exception",
                },
                Trace: trace,
                Kv: []sdk.KeyVal{
                    {
                        Key: "k1",
                        Val: "v1",
                    }, {
                        Key: "k2",
                        Val: "v2",
                    },
                },
                ProtocolMerge: true,
                IsEnd:         true,
            },
            {
                ReqLen:    &reqLen,
                RespLen:   &respLen,
                RequestID: &requestID,
                Req:       nil,
                Resp: &sdk.Response{
                    Status:    &status,
                    Code:      &code,
                    Result:    "result",
                    Exception: "exception",
                },
                Trace: trace,
                Kv: []sdk.KeyVal{
                    {
                        Key: "k3",
                        Val: "",
                    }, {
                        Key: "k4",
                        Val: "v4",
                    },
                },
                ProtocolMerge: true,
                IsEnd:         true,
            },
        })
    default:
        panic("unreachable")
    }
}

func main() {
    sdk.Warn("wasm register parser")
    sdk.SetParser(parser{})
}
*/
