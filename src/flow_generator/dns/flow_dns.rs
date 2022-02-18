use std::time::Duration;

use super::consts::*;

use crate::{
    common::{
        enums::IpProtocol,
        flow::{FlowPerfStats, L7PerfStats, L7Protocol},
        meta_packet::MetaPacket,
        protocol_logs::{AppProtoHead, L7ResponseStatus, LogMessageType},
    },
    error::{Error, Result},
    utils::bytes::read_u16_be,
};

#[derive(Default)]
struct DnsPerfStats {
    // 每次获取统计数据后此结构体都会被清零，不能在其中保存Flow级别的信息避免被清空
    rrt: u64,
    rrt_sum: u64,
    rrt_count: u32,
    request_count: u32,
    response_count: u32,
    error_client_count: u32,
    error_server_count: u32,
}

#[derive(Clone)]
struct DnsSessionData {
    pub id: u16,
    pub qr: u8,
    pub resp_code: u8,
    pub status: L7ResponseStatus,
    pub proto: L7Protocol,
    pub is_dns_data_update: bool,
}

struct DnsPerfData {
    perf_stats: DnsPerfStats,
    session_data: DnsSessionData,
}

impl DnsPerfData {
    /*
     * TODO
     *   1.FlowMap需要添加hash，维护RRT
     */
    pub fn parse(
        &mut self,
        meta: &MetaPacket,
        mismatch_response_count: &mut i64,
        rrt_cache: &mut u64,
        flow_id: u64,
    ) -> Result<()> {
        if meta.lookup_key.src_port != DNS_PORT && meta.lookup_key.dst_port != DNS_PORT {
            return Ok(());
        }

        let payload = meta
            .get_l4_payload()
            .ok_or(Error::DnsPerfParse("dns payload length error".to_string()))?;

        match meta.lookup_key.proto {
            IpProtocol::Udp => self.decode_payload(
                payload,
                meta.lookup_key.timestamp,
                mismatch_response_count,
                rrt_cache,
                flow_id,
            ),
            IpProtocol::Tcp => {
                if payload.len() < DNS_TCP_PAYLOAD_OFFSET {
                    return Err(Error::DnsPerfParse("dns payload length error".to_string()));
                }

                let size = read_u16_be(payload) as usize;
                if size != payload[DNS_TCP_PAYLOAD_OFFSET..].len() {
                    return Err(Error::DnsPerfParse("dns payload length error".to_string()));
                }
                self.decode_payload(
                    payload,
                    meta.lookup_key.timestamp,
                    mismatch_response_count,
                    rrt_cache,
                    flow_id,
                )
            }
            _ => Err(Error::DnsPerfParse(
                "dns translation type error".to_string(),
            )),
        }
    }

    pub fn get_app_proto_head(&self) -> Option<(AppProtoHead, u16)> {
        let DnsSessionData {
            proto,
            qr,
            status,
            resp_code,
            ..
        } = self.session_data;
        if proto != L7Protocol::Dns {
            return None;
        }

        let ret = AppProtoHead {
            proto,
            msg_type: if qr == DNS_OPCODE_RESPONSE {
                LogMessageType::Response
            } else {
                LogMessageType::Request
            },
            status,
            code: resp_code as u16,
            rrt: self.perf_stats.rrt,
        };

        Some((ret, 0))
    }

    pub fn decode_payload(
        &mut self,
        payload: &[u8],
        timestamp: Duration,
        _mismatch_response_count: &mut i64,
        _rrt_cache: &mut u64,
        _flow_id: u64,
    ) -> Result<()> {
        if payload.len() < DNS_HEADER_SIZE {
            return Err(Error::DnsLogParse("protocol mismatch".to_string()));
        }
        self.session_data.id =
            u16::from_le_bytes(*<&[u8; 2]>::try_from(&payload[..DNS_HEADER_FLAGS_OFFSET]).unwrap());
        self.session_data.qr = payload[DNS_HEADER_FLAGS_OFFSET] & DNS_HEADER_QR_MASK;
        self.session_data.resp_code =
            payload[DNS_HEADER_FLAGS_OFFSET + 1] & DNS_HEADER_RESPCODE_MASK;
        self.session_data.is_dns_data_update = true;

        if self.session_data.qr == DNS_OPCODE_REQUEST {
            self.perf_stats.request_count += 1;
        } else if self.session_data.qr == DNS_OPCODE_RESPONSE {
            self.perf_stats.response_count += 1;
            match self.session_data.resp_code {
                DNS_RESPCODE_SUCCESS => {
                    self.session_data.status = L7ResponseStatus::Ok;
                }
                DNS_RESPCODE_FORMAT | DNS_RESPCODE_NXDOMAIN => {
                    self.perf_stats.error_client_count += 1;
                    self.session_data.status = L7ResponseStatus::ClientError;
                }
                _ => {
                    self.perf_stats.error_server_count += 1;
                    self.session_data.status = L7ResponseStatus::ServerError;
                }
            }

            // TODO:get request timestamp
            let dns_rrt = timestamp;
            if dns_rrt < DNS_RRT_MIN || dns_rrt > DNS_RRT_MAX {
                return Ok(());
            }
            self.perf_stats.rrt = dns_rrt.as_secs();
            self.perf_stats.rrt_count += 1;
            self.perf_stats.rrt_sum += dns_rrt.as_secs();
        }

        Ok(())
    }

    pub fn copy_and_reset_l7_perf_data(
        &mut self,
        report: &mut FlowPerfStats,
        number_of_l7_time_out: u32,
    ) {
        let l7 = L7PerfStats {
            request_count: self.perf_stats.request_count,
            response_count: self.perf_stats.response_count,
            err_client_count: self.perf_stats.error_client_count,
            err_server_count: self.perf_stats.error_server_count,
            err_timeout: number_of_l7_time_out,
            rrt_count: self.perf_stats.rrt_count,
            rrt_sum: self.perf_stats.rrt_sum,
            rrt_max: if u64::from(report.l7.rrt_max) < self.perf_stats.rrt {
                self.perf_stats.rrt as u32
            } else {
                report.l7.rrt_max
            },
        };

        report.l7_protocol = L7Protocol::Dns;
        report.l7 = l7;

        self.perf_stats = DnsPerfStats::default();
    }
}
