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

use std::{collections::HashMap, fmt};

use log::{debug, warn};
use nom::{
    bits, bytes,
    combinator::map_res,
    error,
    multi::{many1, many1_count},
    number, sequence, IResult, Parser,
};
use serde::{Serialize, Serializer};

use crate::{
    common::{
        enums::IpProtocol,
        flow::{L7Protocol, PacketDirection},
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    },
    flow_generator::{
        error::{Error, Result},
        protocol_logs::{
            pb_adapter::{L7ProtocolSendLog, L7Request, L7Response},
            value_is_default, value_is_negative, AppProtoHead, L7ResponseStatus, LogMessageType,
        },
    },
};
use public::proto::flow_log::MqttTopic;

#[derive(Serialize, Clone, Debug)]
pub struct MqttInfo {
    #[serde(skip)]
    start_time: u64,
    #[serde(skip)]
    end_time: u64,
    msg_type: LogMessageType,

    #[serde(rename = "request_domain", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "value_is_default")]
    pub version: u8,
    #[serde(rename = "request_type")]
    pub pkt_type: PacketKind,
    #[serde(rename = "request_length", skip_serializing_if = "value_is_negative")]
    pub req_msg_size: Option<u32>,
    #[serde(rename = "response_length", skip_serializing_if = "value_is_negative")]
    pub res_msg_size: Option<u32>,
    #[serde(
        rename = "request_resource",
        skip_serializing_if = "Option::is_none",
        serialize_with = "topics_format"
    )]
    pub subscribe_topics: Option<Vec<MqttTopic>>,
    #[serde(skip)]
    pub publish_topic: Option<String>,
    #[serde(rename = "response_code", skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>, // connect_ack packet return code
    pub status: L7ResponseStatus,
}

impl L7ProtocolInfoInterface for MqttInfo {
    fn session_id(&self) -> Option<u32> {
        None
    }

    fn merge_log(&mut self, other: L7ProtocolInfo) -> Result<()> {
        if let L7ProtocolInfo::MqttInfo(mqtt) = other {
            if mqtt.start_time < self.start_time {
                self.start_time = mqtt.start_time;
            }
            if mqtt.end_time > self.end_time {
                self.end_time = mqtt.end_time;
            }
            self.merge(mqtt);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::MQTT,
            msg_type: self.msg_type,
            rrt: self.end_time - self.start_time,
        })
    }

    fn is_tls(&self) -> bool {
        false
    }
}

pub fn topics_format<S>(t: &Option<Vec<MqttTopic>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ts = t.as_ref().unwrap();
    let names = ts.iter().map(|c| c.name.clone()).collect::<Vec<_>>();
    serializer.serialize_str(&names.join(","))
}

impl Default for MqttInfo {
    fn default() -> Self {
        Self {
            client_id: None,
            version: 0,
            pkt_type: Default::default(),
            req_msg_size: None,
            res_msg_size: None,
            subscribe_topics: None,
            publish_topic: None,
            code: None,
            status: L7ResponseStatus::Ok,
            start_time: 0,
            end_time: 0,
            msg_type: LogMessageType::Other,
        }
    }
}

impl MqttInfo {
    pub fn merge(&mut self, other: Self) {
        if self.res_msg_size.is_none() {
            self.res_msg_size = other.res_msg_size;
        }
        if self.status == L7ResponseStatus::default() {
            self.status = other.status;
        }
        if self.code.is_none() {
            self.code = other.code;
        }
        match other.pkt_type {
            PacketKind::Publish { .. } => {
                self.publish_topic = other.publish_topic;
            }
            PacketKind::Unsubscribe | PacketKind::Subscribe => {
                self.subscribe_topics = other.subscribe_topics;
            }
            _ => (),
        }
    }

    pub fn get_version_str(&self) -> &'static str {
        match self.version {
            3 => "3.1",
            4 => "3.1.1",
            5 => "5.0",
            _ => "",
        }
    }
}

impl From<MqttInfo> for L7ProtocolSendLog {
    fn from(f: MqttInfo) -> Self {
        let version = Some(String::from(f.get_version_str()));
        let mut topic_str = String::new();
        match f.pkt_type {
            PacketKind::Publish { .. } => {
                if let Some(t) = f.publish_topic {
                    topic_str.push_str(t.as_str());
                }
            }
            PacketKind::Unsubscribe | PacketKind::Subscribe => {
                if let Some(s) = f.subscribe_topics {
                    for i in s {
                        topic_str.push_str(format!("{},", i.name).as_str());
                    }
                    if !topic_str.is_empty() {
                        topic_str.pop();
                    }
                }
            }
            _ => {}
        };
        let log = L7ProtocolSendLog {
            version: version,
            req_len: f.req_msg_size,
            resp_len: f.res_msg_size,
            req: L7Request {
                req_type: f.pkt_type.to_string(),
                domain: f.client_id.unwrap_or_default(),
                resource: topic_str,
                ..Default::default()
            },
            resp: L7Response {
                status: f.status,
                code: f.code,
                ..Default::default()
            },
            ..Default::default()
        };
        return log;
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MqttLog {
    info: Vec<MqttInfo>,
    msg_type: LogMessageType,
    status: L7ResponseStatus,
    version: u8,
    client_map: HashMap<u64, String>,

    start_time: u64,
    end_time: u64,
}

impl L7ProtocolParserInterface for MqttLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        Self::mqtt_check_protocol(payload, param)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<Vec<L7ProtocolInfo>> {
        self.parse(payload, param.l4_protocol, param.direction, None, None)?;
        let mut v = vec![];
        for i in self.info.iter() {
            let mut info = i.clone();
            info.msg_type = self.msg_type;
            info.start_time = self.start_time;
            info.end_time = self.end_time;
            v.push(L7ProtocolInfo::MqttInfo(info));
        }
        Ok(v)
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::MQTT
    }

    fn parsable_on_udp(&self) -> bool {
        false
    }

    fn reset(&mut self) {
        let mut s = Self::default();
        s.version = self.version;
        *self = s;
    }
}

impl MqttLog {
    fn parse_mqtt_info(&mut self, mut payload: &[u8]) -> Result<()> {
        // 现在只支持MQTT 3.1.1解析，不支持v5.0
        // Now only supports MQTT 3.1.1 parsing, not support v5.0
        if self.version != 0 && self.version != 4 {
            warn!("cannot parse packet, log parser only support to parse MQTT V3.1.1 packet");
            return Err(Error::MqttLogParseFailed);
        }

        loop {
            let (input, header) =
                mqtt_fixed_header(payload).map_err(|_| Error::MqttLogParseFailed)?;
            let mut info = MqttInfo::default();
            match header.kind {
                PacketKind::Connect => {
                    let data = bytes::complete::take(header.remaining_length as u32);
                    let (_, (version, client_id)) = data
                        .and_then(parse_connect_packet)
                        .parse(input)
                        .map_err(|_| Error::MqttLogParseFailed)?;
                    info.version = version;
                    info.client_id = Some(client_id.to_string());
                    self.msg_type = LogMessageType::Request;
                    info.req_msg_size = Some(header.remaining_length as u32);
                    info.pkt_type = header.kind;
                    self.version = version;
                }
                PacketKind::Connack => {
                    let (_, return_code) =
                        parse_connack_packet(input).map_err(|_| Error::MqttLogParseFailed)?;
                    info.code = Some(return_code as i32);
                    info.version = self.version;
                    self.msg_type = LogMessageType::Response;
                    info.res_msg_size = Some(header.remaining_length as u32);
                    info.pkt_type = header.kind;
                    self.status = parse_status_code(return_code);
                }
                PacketKind::Publish { dup, qos, .. } => {
                    let (_, topic_name) =
                        mqtt_string(input).map_err(|_| Error::MqttLogParseFailed)?;
                    if dup && qos == QualityOfService::AtMostOnce {
                        debug!("mqtt publish packet has invalid dup flags={}", dup);
                        return Err(Error::MqttLogParseFailed);
                    }
                    // QOS=1,2会有报文标识符
                    // QOS=1,2 there will be a message identifier
                    if qos == QualityOfService::AtLeastOnce || qos == QualityOfService::ExactlyOnce
                    {
                        self.msg_type = LogMessageType::Request;
                        info.req_msg_size = Some(header.remaining_length as u32);
                    } else {
                        self.msg_type = LogMessageType::Response;
                        info.res_msg_size = Some(header.remaining_length as u32);
                    };
                    info.publish_topic.replace(topic_name.to_string());
                    info.pkt_type = header.kind;
                    info.version = self.version;
                }
                PacketKind::Subscribe => {
                    // 跳过解析报文标识符
                    // skip parsing packet identifier
                    let (_, (_, result)) = mqtt_packet_identifier
                        .and(mqtt_subscription_requests)
                        .parse(input)
                        .map_err(|_| Error::MqttLogParseFailed)?;
                    self.msg_type = LogMessageType::Request;
                    info.req_msg_size = Some(header.remaining_length as u32);
                    info.pkt_type = header.kind;
                    info.version = self.version;
                    info.subscribe_topics.replace(
                        result
                            .into_iter()
                            .map(|(t, qos)| MqttTopic {
                                name: t.to_string(),
                                qos: qos as i32,
                            })
                            .collect(),
                    );
                }
                PacketKind::Unsubscribe => {
                    let (_, (_, reqs)) = mqtt_packet_identifier
                        .and(mqtt_unsubscription_requests)
                        .parse(input)
                        .map_err(|_| Error::MqttLogParseFailed)?;
                    self.msg_type = LogMessageType::Request;
                    info.req_msg_size = Some(header.remaining_length as u32);
                    info.pkt_type = header.kind;
                    info.version = self.version;
                    info.subscribe_topics.replace(
                        reqs.into_iter()
                            .map(|topic| MqttTopic {
                                name: topic.to_string(),
                                qos: -1,
                            })
                            .collect(),
                    );
                }
                PacketKind::Pingreq | PacketKind::Pubrel => {
                    info.pkt_type = header.kind;
                    info.version = self.version;
                    info.req_msg_size = Some(header.remaining_length as u32);
                    self.msg_type = LogMessageType::Request;
                }
                PacketKind::Suback
                | PacketKind::Pingresp
                | PacketKind::Pubcomp
                | PacketKind::Pubrec
                | PacketKind::Puback
                | PacketKind::Unsuback => {
                    info.pkt_type = header.kind;
                    info.version = self.version;
                    self.msg_type = LogMessageType::Response;
                    info.res_msg_size = Some(header.remaining_length as u32);
                }
                PacketKind::Disconnect => {
                    info.pkt_type = header.kind;
                    self.msg_type = LogMessageType::Session;
                    info.res_msg_size = Some(header.remaining_length as u32);
                    info.version = self.version;
                }
            }

            info.status = self.status;
            self.info.push(info);

            if input.len() <= header.remaining_length as usize {
                break;
            }
            payload = &input[header.remaining_length as usize..];
        }

        if self.info.is_empty() {
            return Err(Error::MqttLogParseFailed);
        }
        Ok(())
    }

    /// 尽力而为解析判断是否为mqtt报文, 因为"不依赖端口判断协议实现"要求首个请求包返回true，其他为false，
    /// 所以只判断是不是合法Connect包
    /// pest effort parsing to determine whether it is an mqtt packet, because "judging protocol implementation
    /// independent of protocol port" requires the first request packet to return true, the others are false,
    /// so only judge whether it is a legitimate "Connect" packet
    pub fn mqtt_check_protocol(payload: &[u8], param: &ParseParam) -> bool {
        if param.l4_protocol != IpProtocol::Tcp {
            return false;
        }

        let (input, header) = match mqtt_fixed_header(payload) {
            Ok(p) => p,
            Err(_) => return false,
        };

        if let PacketKind::Connect = header.kind {
            let data = bytes::complete::take(header.remaining_length as u32);
            let version = match data.and_then(parse_connect_packet).parse(input) {
                Ok((_, (version, _))) => version,
                Err(_) => return false,
            };
            if version < 3 || version > 5 {
                return false;
            }
            return true;
        }

        false
    }

    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        _direction: PacketDirection,
        _is_req_end: Option<bool>,
        _is_resp_end: Option<bool>,
    ) -> Result<()> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }
        self.status = L7ResponseStatus::Ok;
        self.info.clear();

        self.parse_mqtt_info(payload).map_err(|e| {
            self.status = L7ResponseStatus::Error;
            e
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub kind: PacketKind,
    pub remaining_length: i32,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Connect,
    Connack,
    Publish {
        dup: bool,
        qos: QualityOfService,
        retain: bool,
    },
    Puback,
    Pubrec,
    Pubrel,
    Pubcomp,
    Subscribe,
    Suback,
    Unsubscribe,
    Unsuback,
    Pingreq,
    Pingresp,
    Disconnect,
}

impl fmt::Display for PacketKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Connect => write!(f, "CONNECT"),
            Self::Connack => write!(f, "CONNACK"),
            Self::Publish { .. } => write!(f, "PUBLISH"),
            Self::Puback => write!(f, "PUBACK"),
            Self::Pubrec => write!(f, "PUBREC"),
            Self::Pubrel => write!(f, "PUBREL"),
            Self::Pubcomp => write!(f, "PUBCOMP"),
            Self::Subscribe => write!(f, "SUBSCRIBE"),
            Self::Suback => write!(f, "SUBACK"),
            Self::Unsubscribe => write!(f, "UNSUBSCRIBE"),
            Self::Unsuback => write!(f, "UNSUBACK"),
            Self::Pingreq => write!(f, "PINGREQ"),
            Self::Pingresp => write!(f, "PINGRESP"),
            Self::Disconnect => write!(f, "DISCONNECT"),
        }
    }
}

impl Default for PacketKind {
    fn default() -> Self {
        Self::Disconnect
    }
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityOfService {
    AtMostOnce = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
}

impl Default for QualityOfService {
    fn default() -> Self {
        Self::AtMostOnce
    }
}

fn mqtt_packet_kind(input: &[u8]) -> IResult<&[u8], PacketKind> {
    let (input, (upper, lower)): (_, (u8, u8)) =
        bits::bits::<_, _, error::Error<(&[u8], usize)>, _, _>(sequence::tuple((
            bits::complete::take(4usize),
            bits::complete::take(4usize),
        )))(input)?;

    let (input, kind) = match (upper, lower) {
        (1, 0b0000) => (input, PacketKind::Connect),
        (2, 0b0000) => (input, PacketKind::Connack),
        (3, lower) => {
            let dup = lower & 0b1000 != 0;
            let retain = lower & 0b0001 != 0;
            let qos = match (lower & 0b0110) >> 1 {
                0b00 => QualityOfService::AtMostOnce,
                0b01 => QualityOfService::AtLeastOnce,
                0b10 => QualityOfService::ExactlyOnce,
                a => {
                    debug!(
                        "parse mqtt packet with type=publish failed because get invalid qos={}",
                        a
                    );
                    return Err(nom::Err::Error(error::Error::new(
                        input,
                        error::ErrorKind::MapRes,
                    )));
                }
            };
            (input, PacketKind::Publish { qos, dup, retain })
        }
        (4, 0b0000) => (input, PacketKind::Puback),
        (5, 0b0000) => (input, PacketKind::Pubrec),
        (6, 0b0010) => (input, PacketKind::Pubrel),
        (7, 0b0000) => (input, PacketKind::Pubcomp),
        (8, 0b0010) => (input, PacketKind::Subscribe),
        (9, 0b0000) => (input, PacketKind::Suback),
        (10, 0b0010) => (input, PacketKind::Unsubscribe),
        (11, 0b0000) => (input, PacketKind::Unsuback),
        (12, 0b0000) => (input, PacketKind::Pingreq),
        (13, 0b0000) => (input, PacketKind::Pingresp),
        (14, 0b0000) => (input, PacketKind::Disconnect),
        (inv_type, _) => {
            debug!(
                "parse mqtt packet failed because get invalid type={}",
                inv_type
            );
            return Err(nom::Err::Error(error::Error::new(
                input,
                error::ErrorKind::MapRes,
            )));
        }
    };

    Ok((input, kind))
}

fn decode_variable_length(input: &[u8]) -> IResult<&[u8], u32> {
    let mut len: usize = 0;
    let mut done = false;
    let mut len_len = 0;
    let mut shift = 0;

    // Use continuation bit at position 7 to continue reading next
    // byte to frame 'length'.
    // Stream 0b1xxx_xxxx 0b1yyy_yyyy 0b1zzz_zzzz 0b0www_wwww will
    // be framed as number 0bwww_wwww_zzz_zzzz_yyy_yyyy_xxx_xxxx
    for &byte in input.iter() {
        len_len += 1;
        let byte = byte as usize;
        len += (byte & 0x7F) << shift;

        // stop when continue bit is 0
        done = (byte & 0x80) == 0;
        if done {
            break;
        }

        shift += 7;

        // Only a max of 4 bytes allowed for remaining length
        // more than 4 shifts (0, 7, 14, 21) implies bad length
        if shift > 21 {
            return Err(nom::Err::Error(error::Error::new(
                input,
                error::ErrorKind::TooLarge,
            )));
        }
    }

    // Not enough bytes to frame remaining length. wait for
    // one more byte
    if !done {
        return Err(nom::Err::Error(error::Error::new(
            input,
            error::ErrorKind::Fail,
        )));
    }

    Ok((&input[len_len..], len as u32))
}

pub fn mqtt_fixed_header(input: &[u8]) -> IResult<&[u8], PacketHeader> {
    let (input, kind) = mqtt_packet_kind(input)?;
    let (input, remaining_length) = decode_variable_length(input)?;

    Ok((
        input,
        PacketHeader {
            kind,
            remaining_length: remaining_length as i32,
        },
    ))
}

fn mqtt_packet_identifier(input: &[u8]) -> IResult<&[u8], u16> {
    number::complete::be_u16(input)
}

fn mqtt_string(input: &[u8]) -> IResult<&[u8], &str> {
    fn control_characters(c: char) -> bool {
        ('\u{0001}'..='\u{001F}').contains(&c) || ('\u{007F}'..='\u{009F}').contains(&c)
    }
    let len = number::complete::be_u16;
    let string_data = len.flat_map(bytes::complete::take);

    map_res(map_res(string_data, std::str::from_utf8), |s| {
        if s.contains(control_characters) {
            debug!("The input contained control characters, which this implementation rejects.");
            Err(nom::Err::Error(error::Error::new(
                input,
                error::ErrorKind::Alpha,
            )))
        } else {
            Ok(s)
        }
    })
    .parse(input)
}

pub fn parse_connect_packet(input: &[u8]) -> IResult<&[u8], (u8, &str)> {
    let (input, protocol_name) = mqtt_string(input)?;
    if protocol_name != "MQTT" {
        debug!("invalid protocol name: {}", protocol_name);
        return Err(nom::Err::Error(error::Error::new(
            input,
            error::ErrorKind::Alpha,
        )));
    }

    let (input, protocol_level) = number::complete::u8(input)?;
    let (input, _) = number::complete::be_u16(&input[1..])?;
    // Payload
    let (input, client_id) = mqtt_string(input)?;
    Ok((input, (protocol_level, client_id)))
}

pub fn parse_connack_packet(input: &[u8]) -> IResult<&[u8], u8> {
    let (input, (reserved, _)): (_, (u8, u8)) =
        bits::bits::<_, _, error::Error<(&[u8], usize)>, _, _>(sequence::tuple((
            bits::complete::take(7usize),
            bits::complete::take(1usize),
        )))(input)?;

    if reserved != 0 {
        return Err(nom::Err::Error(error::Error::new(
            input,
            error::ErrorKind::MapRes,
        )));
    }

    let (input, connect_return_code) = number::complete::u8(input)?;

    Ok((input, connect_return_code))
}

pub fn parse_status_code(code: u8) -> L7ResponseStatus {
    match code {
        /*
        Accepted = 0x0,
        ProtocolNotAccepted = 0x1,
        IdentifierRejected = 0x2,
        ServerUnavailable = 0x3,
        BadUsernamePassword = 0x4,
        NotAuthorized = 0x5,
        */
        0 => L7ResponseStatus::Ok,
        1 | 2 | 4 | 5 => L7ResponseStatus::ClientError,
        3 => L7ResponseStatus::ServerError,
        _ => L7ResponseStatus::NotExist,
    }
}

fn mqtt_subscription_requests(input: &[u8]) -> IResult<&[u8], Vec<(&str, QualityOfService)>> {
    fn subscription_request(input: &[u8]) -> IResult<&[u8], (&str, QualityOfService)> {
        let (input, topic) = mqtt_string(input)?;
        let (input, qos) = map_res(number::complete::u8, mqtt_quality_of_service).parse(input)?;
        Ok((input, (topic, qos)))
    }

    let (input, count) = many1(subscription_request)(input)?;
    Ok((input, count))
}

fn mqtt_quality_of_service(lower: u8) -> Result<QualityOfService, u8> {
    match lower {
        0b00 => Ok(QualityOfService::AtMostOnce),
        0b01 => Ok(QualityOfService::AtLeastOnce),
        0b10 => Ok(QualityOfService::ExactlyOnce),
        inv_qos => Err(inv_qos),
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscriptionAck {
    MaximumQualityAtMostOnce = 0x00,
    MaximumQualityAtLeastOnce = 0x01,
    MaximumQualityExactlyOnce = 0x02,
    Failure = 0x80,
}

fn mqtt_subscription_ack(input: &[u8]) -> IResult<&[u8], SubscriptionAck> {
    let (input, data) = number::complete::u8(input)?;

    Ok((
        input,
        match data {
            0x00 => SubscriptionAck::MaximumQualityAtMostOnce,
            0x01 => SubscriptionAck::MaximumQualityAtLeastOnce,
            0x02 => SubscriptionAck::MaximumQualityExactlyOnce,
            0x80 => SubscriptionAck::Failure,
            _ => {
                return Err(nom::Err::Error(error::Error::new(
                    input,
                    error::ErrorKind::MapRes,
                )))
            }
        },
    ))
}

fn mqtt_subscription_acks(input: &[u8]) -> IResult<&[u8], &[SubscriptionAck]> {
    let acks = input;
    let (input, acks_len) = many1_count(mqtt_subscription_ack)(input)?;

    assert!(acks_len <= acks.len());

    let ack_ptr: *const SubscriptionAck = acks.as_ptr() as *const SubscriptionAck;
    let acks: &[SubscriptionAck] = unsafe {
        // SAFETY: The array has been checked and is of the correct len, as well as
        // SubscriptionAck is the same repr and has no padding
        std::slice::from_raw_parts(ack_ptr, acks_len)
    };

    Ok((input, acks))
}

fn mqtt_unsubscription_requests(input: &[u8]) -> IResult<&[u8], Vec<&str>> {
    let (input, reqs) = many1(mqtt_string)(input)?;
    Ok((input, reqs))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{
        common::{flow::PacketDirection, MetaPacket},
        utils::test::Capture,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/mqtt";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), Some(1024));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut mqtt = MqttLog::default();
        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            packet.lookup_key.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };
            let _ = mqtt.parse(
                payload,
                packet.lookup_key.proto,
                packet.lookup_key.direction,
                None,
                None,
            );
            let is_mqtt =
                MqttLog::mqtt_check_protocol(payload, &ParseParam::from(packet as &MetaPacket));
            for i in mqtt.info.iter() {
                output.push_str(&format!("{:?} is_mqtt: {}\r\n", i, is_mqtt));
            }
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("mqtt_connect.pcap", "mqtt_connect.result"),
            ("mqtt_error.pcap", "mqtt_error.result"),
            ("mqtt_roundtrip.pcap", "mqtt_roundtrip.result"),
            (
                "mqtt_one_packet_multi_publish.pcap",
                "mqtt_one_packet_multi_publish.result",
            ),
            ("mqtt_pub.pcap", "mqtt_pub.result"),
        ];

        for item in files.iter() {
            let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
            let output = run(item.0);

            if output != expected {
                let output_path = Path::new("actual.txt");
                fs::write(&output_path, &output).unwrap();
                assert!(
                    output == expected,
                    "output different from expected {}, written to {:?}",
                    item.1,
                    output_path
                );
            }
        }
    }

    #[test]
    fn check_variable_length_decoding() {
        let input = &[64];

        let (input, output) = decode_variable_length(input).unwrap();
        assert_eq!(output, 64);
        assert_eq!(input.len(), 0);

        let input = &[193, 2];

        let (input, output) = decode_variable_length(input).unwrap();
        assert_eq!(output, 321);
        assert_eq!(input.len(), 0);
    }

    #[test]
    fn check_header_publish_flags() {
        let input = &[0b0011_1101, 0];

        let (input, header) = mqtt_fixed_header(input).unwrap();

        assert_eq!(input.len(), 0);

        assert_eq!(
            header,
            PacketHeader {
                remaining_length: 0,
                kind: PacketKind::Publish {
                    dup: true,
                    qos: QualityOfService::ExactlyOnce,
                    retain: true
                }
            }
        );
    }

    #[test]
    fn check_invalid_header_publish_flags() {
        let input = &[0b0011_1111, 0];

        mqtt_fixed_header(input).unwrap_err();
    }

    #[test]
    fn test_subscription() {
        let input = &[
            0, 3, // Length 3
            0x61, 0x2F, 0x62, // The string 'a/b'
            1,    // QoS 1
            0, 3, // Length 3
            0x63, 0x2F, 0x64, // The string 'c/d'
            2,    // QoS 2
        ];

        let (rest, subs) = mqtt_subscription_requests(input).unwrap();
        assert_eq!(rest.len(), 0);
        assert_eq!(
            subs,
            vec![
                ("a/b", QualityOfService::AtLeastOnce),
                ("c/d", QualityOfService::ExactlyOnce)
            ]
        );
    }

    #[test]
    fn check_connect_roundtrip() {
        let input = &[
            0b0001_0000,
            37,
            0x0,
            0x4, // String length
            b'M',
            b'Q',
            b'T',
            b'T',
            0x4,         // Level
            0b1111_0110, // Connect flags
            0x0,
            0x10, // Keel Alive in secs
            0x0,  // Client Identifier
            0x5,
            b'H',
            b'E',
            b'L',
            b'L',
            b'O',
            0x0, // Will Topic
            0x5,
            b'W',
            b'O',
            b'R',
            b'L',
            b'D',
            0x0, // Will Payload
            0x1,
            0xFF,
            0x0,
            0x5, // Username
            b'A',
            b'D',
            b'M',
            b'I',
            b'N',
            0x0,
            0x1, // Password
            0xF0,
        ];
        let (input, header) = mqtt_fixed_header(input).unwrap();
        match header.kind {
            PacketKind::Connect => {
                let data = bytes::complete::take(header.remaining_length as u32);
                let (_, packet) = data.and_then(parse_connect_packet).parse(input).unwrap();
                assert_eq!(packet, (4, "HELLO"));
            }
            _ => (),
        }
    }

    #[test]
    fn check_simple_string() {
        let input = [0x00, 0x05, 0x41, 0xF0, 0xAA, 0x9B, 0x94];

        let s = mqtt_string(&input);

        assert_eq!(s, Ok((&[][..], "A\u{2A6D4}")))
    }
}
