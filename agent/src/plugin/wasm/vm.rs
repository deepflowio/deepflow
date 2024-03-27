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

use std::mem::ManuallyDrop;
use std::net::IpAddr;

use crate::common::ebpf::EbpfType;
use crate::common::flow::PacketDirection;
use crate::common::l7_protocol_log::ParseParam;
use crate::flow_generator::protocol_logs::{HttpInfo, L7ResponseStatus};
use crate::flow_generator::{Error, Result};
use crate::plugin::CustomInfo;
use crate::wasm_error;

use log::error;
use public::bytes::{write_u16_be, write_u64_be};
use public::enums::IpProtocol;

// result of the vm export function after serialize
#[derive(Debug)]
pub(super) enum VmResult {
    // result of parse_payload
    L7InfoResult(Vec<CustomInfo>),
    StringResult(String),
}

// vm parse ctx
pub(super) enum VmParseCtx {
    ParseCtx(VmCtxBase),
    HttpReqCtx(VmHttpReqCtx),
    HttpRespCtx(VmHttpRespCtx),
}

impl VmParseCtx {
    pub(super) fn get_ctx_base(&self) -> &VmCtxBase {
        match self {
            VmParseCtx::ParseCtx(c) => c,
            VmParseCtx::HttpReqCtx(c) => &c.base_ctx,
            VmParseCtx::HttpRespCtx(c) => &c.base_ctx,
        }
    }

    pub(super) fn get_ctx_base_mut(&mut self) -> &mut VmCtxBase {
        match self {
            VmParseCtx::ParseCtx(c) => c,
            VmParseCtx::HttpReqCtx(c) => &mut c.base_ctx,
            VmParseCtx::HttpRespCtx(c) => &mut c.base_ctx,
        }
    }

    pub(super) fn set_ins_name(&mut self, ins_name: String) {
        self.get_ctx_base_mut().instance_name = ins_name;
    }

    pub(super) fn get_ins_name(&self) -> &str {
        self.get_ctx_base().instance_name.as_str()
    }

    fn take_result(&mut self) -> Option<VmResult> {
        self.get_ctx_base_mut().result.take()
    }

    pub(super) fn take_l7_info_result(&mut self) -> Option<Vec<CustomInfo>> {
        self.take_result().map_or(None, |r| match r {
            VmResult::L7InfoResult(info) => Some(info),
            _ => {
                wasm_error!(
                    self.get_ins_name(),
                    "parse payload result with unexpect type",
                );
                None
            }
        })
    }

    pub(super) fn take_str_result(&mut self) -> Option<String> {
        self.take_result().map_or(None, |r| match r {
            VmResult::StringResult(s) => Some(s),
            _ => {
                wasm_error!(self.get_ins_name(), "str result with unexpect type",);
                None
            }
        })
    }

    pub(super) fn serialize_ctx_base(&self, buf: &mut [u8]) -> Result<usize> {
        self.get_ctx_base().serialize_to_bytes(buf)
    }
}

/*
    correspond to go struct ParseCtx:

    type ParseCtx struct {
        Src      net.IPAddr
        Dst      net.IPAddr
        l4       L4Protocol
        l7       uint16
        EbpfType EbpfType
        Time     uint64 // micro second
        Direction Direction
        ProcName string
        Payload  []byte
    }
*/
pub struct VmCtxBase {
    // parser ctx, set in check and parse payload
    pub(super) ip_src: IpAddr,
    pub(super) ip_dst: IpAddr,
    pub(super) port_src: u16,
    pub(super) port_dst: u16,
    pub(super) l4_protocol: IpProtocol,
    // proto is return from on_check_payload, when on_check_payload, it set to 0, other wise will set to non zero value
    pub(super) proto: u8,
    pub(super) ebpf_type: EbpfType,
    pub(super) time: u64,
    pub(super) direction: PacketDirection,
    pub(super) process_kname: Option<String>,
    pub(super) flow_id: u64,
    pub(super) buf_size: u16,

    /*
        payload is from the payload: &[u8] in L7ProtocolParserInterface::check_payload() and L7ProtocolParserInterface::parse_payload(),
        it can not modify and drop.
    */
    pub(super) payload: ManuallyDrop<Vec<u8>>,

    /*
        in every function call, traversal all instance and call correspond function in instance.
        it will set the current instance  name which calling the function, now only use for log.
    */
    instance_name: String,

    result: Option<VmResult>,
}

impl From<(&ParseParam<'_>, u8, &[u8])> for VmCtxBase {
    fn from(p: (&ParseParam<'_>, u8, &[u8])) -> Self {
        let (p, wasm_proto, payload) = p;

        Self {
            ip_src: p.ip_src,
            ip_dst: p.ip_dst,
            port_src: p.port_src,
            port_dst: p.port_dst,
            l4_protocol: p.l4_protocol,
            proto: wasm_proto,
            ebpf_type: p.ebpf_type,
            time: p.time,
            direction: p.direction,
            process_kname: if let Some(ebpf_param) = p.ebpf_param.as_ref() {
                Some(ebpf_param.process_kname.to_owned())
            } else {
                None
            },
            flow_id: p.flow_id,
            buf_size: p.buf_size,
            /*
                it is safe to use unsafe because VmParseCtx use in check, parse or other place will drop before the function call finish.
                the lifetime of VmParseCtx always shorter than payload which from L7ProtocolParserInterface::check_payload() and L7ProtocolParserInterface::parse_payload().
                it will not modify in whole lifetime of VmParseCtx
            */
            payload: ManuallyDrop::new(unsafe {
                Vec::from_raw_parts(
                    payload.as_ptr() as usize as *mut u8,
                    payload.len(),
                    payload.len(),
                )
            }),
            instance_name: "".to_string(),

            result: None,
        }
    }
}

impl VmCtxBase {
    /*
        serial format as follow, be encode

        ip type:     1 byte, 4 and 6 indicate  ipv4/ipv6
        src_ip:      4/16 bytes
        dst_ip:      4/16 bytes
        src_port:    2 bytes
        dst_port:    2 bytes

        l4 protocol: 1 byte, 6/17 indicate udp/tcp
        l7 protocol: 1 byte

        ebpf type:   1 byte

        time:        8 bytes

        direction:   1 byte, 0/1 indicate c2s/s2c

        proc name len:  1 byte

        proc name: 		$(proc name len) len

        flow_id:     8 bytes

        buf_size:    2 bytes, the config of l7_log_packet_size
    */
    fn serialize_to_bytes(&self, buf: &mut [u8]) -> Result<usize> {
        let serialize_len = if self.ip_src.is_ipv6() { 32 } else { 8 }
            + 28
            + if let Some(proc_name) = self.process_kname.as_ref() {
                proc_name.len()
            } else {
                0
            };
        if buf.len() < serialize_len {
            return Err(Error::WasmSerializeFail(format!(
                "serialize ctx base fail, need {} bytes but buf only {} bytes",
                serialize_len,
                buf.len()
            )));
        }

        let mut off = 0usize;

        buf[0] = if self.ip_src.is_ipv6() { 6u8 } else { 4u8 };
        match self.ip_src {
            IpAddr::V4(v4) => {
                buf[1..5].copy_from_slice(v4.octets().as_slice());
                off += 5;
            }
            IpAddr::V6(v6) => {
                buf[1..17].copy_from_slice(v6.octets().as_slice());
                off += 17;
            }
        }

        match self.ip_dst {
            IpAddr::V4(v4) => {
                buf[off..off + 4].copy_from_slice(v4.octets().as_slice());
                off += 4;
            }
            IpAddr::V6(v6) => {
                buf[off..off + 16].copy_from_slice(v6.octets().as_slice());
                off += 16;
            }
        }

        write_u16_be(&mut buf[off..off + 2], self.port_src);
        write_u16_be(&mut buf[off + 2..off + 4], self.port_dst);
        off += 4;

        match self.l4_protocol {
            IpProtocol::TCP => buf[off] = 6,
            IpProtocol::UDP => buf[off] = 17,
            _ => unreachable!(),
        }
        buf[off + 1] = self.proto;
        buf[off + 2] = self.ebpf_type as u8;
        off += 3;

        write_u64_be(&mut buf[off..off + 8], self.time);
        off += 8;

        buf[off] = self.direction as u8;
        off += 1;

        if let Some(proc_name) = self.process_kname.as_ref() {
            buf[off] = proc_name.len() as u8;
            off += 1;
            (&mut buf[off..off + proc_name.len()]).copy_from_slice(proc_name.as_bytes());
            off += proc_name.len();
        } else {
            buf[off] = 0;
            off += 1
        }

        write_u64_be(&mut buf[off..], self.flow_id);
        off += 8;

        write_u16_be(&mut buf[off..], self.buf_size);
        off += 2;

        Ok(off)
    }

    pub(super) fn set_result(&mut self, result: VmResult) {
        self.result = Some(result);
    }
}

/*
    correspond to go struct HttpReqCtx:

    type HttpReqCtx struct {
        BaseCtx    ParseCtx
        Path        string
        ContentType string
    }
*/
pub struct VmHttpReqCtx {
    pub base_ctx: VmCtxBase,

    pub path: String,
    pub host: String,
    pub user_agent: String,
    pub referer: String,
}

macro_rules! serialize_str_ctx {
    ($self: ident, $buf: expr, $off: ident, $field: ident) => {
        write_u16_be(&mut $buf[$off..$off + 2], $self.$field.len() as u16);
        $off += 2;
        $buf[$off..$off + $self.$field.len()].copy_from_slice($self.$field.as_bytes());
        $off += $self.$field.len();
    };
}

impl VmHttpReqCtx {
    /*
        path len:  2 byte
        path:      $(path len) byte

        host len:     2 byte
        host:         $(host len) byte

        ua len:     2 byte
        ua:         $(ua len) byte

        referer len:  2 byte
        referer:      $(referer) byte
    */
    pub(super) fn serialize_to_bytes(&self, buf: &mut [u8]) -> Result<usize> {
        let need_size =
            8 + self.path.len() + self.host.len() + self.user_agent.len() + self.referer.len();
        if buf.len() < need_size {
            return Err(Error::WasmSerializeFail(format!(
                "serialize http req ctx fail, need at lease {} bytes but buf only {} bytes",
                need_size,
                buf.len()
            )));
        }

        let mut off = 0;

        serialize_str_ctx!(self, buf, off, path);
        serialize_str_ctx!(self, buf, off, host);
        serialize_str_ctx!(self, buf, off, user_agent);
        serialize_str_ctx!(self, buf, off, referer);
        Ok(off)
    }
}

impl From<(&ParseParam<'_>, &HttpInfo, &[u8])> for VmHttpReqCtx {
    fn from(value: (&ParseParam<'_>, &HttpInfo, &[u8])) -> Self {
        let (param, info, payload) = value;
        Self {
            base_ctx: VmCtxBase::from((param, info.proto as u8, payload)),
            path: info.path.clone(),
            host: info.host.clone(),
            user_agent: info
                .user_agent
                .as_ref()
                .map_or("".to_string(), |s| s.clone()),
            referer: info.referer.as_ref().map_or("".to_string(), |s| s.clone()),
        }
    }
}

/*
    correspond to go struct HttpRespCtx:

    type HttpReqCtx struct {
        BaseCtx ParseCtx
        Code     uint16
    }
*/
pub struct VmHttpRespCtx {
    pub base_ctx: VmCtxBase,
    pub code: u16,
    pub status: L7ResponseStatus,
}

impl VmHttpRespCtx {
    /*
      code:      2 bytes
      status:    1 bytes
    */
    const BUF_SIZE: usize = 3;
    pub(super) fn serialize_to_bytes(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < Self::BUF_SIZE {
            return Err(Error::WasmSerializeFail(format!(
                "serialize http resp ctx fail, need at lease {} bytes but buf only {} bytes",
                Self::BUF_SIZE,
                buf.len()
            )));
        }

        let mut off = 0;
        write_u16_be(buf, self.code);
        off += 2;
        buf[off] = self.status as u8;
        off += 1;
        Ok(off)
    }
}

impl From<(&ParseParam<'_>, &HttpInfo, &[u8])> for VmHttpRespCtx {
    fn from(value: (&ParseParam, &HttpInfo, &[u8])) -> Self {
        let (param, info, payload) = value;
        Self {
            base_ctx: VmCtxBase::from((param, info.proto as u8, payload)),
            code: info.status_code,
            status: info.status,
        }
    }
}
