use super::super::{
    consts::*, AppProtoHead, AppProtoLogsInfo, L7LogParse, L7Protocol, L7ResponseStatus,
    LogMessageType,
};

use crate::{
    common::enums::{IpProtocol, PacketDirection},
    common::meta_packet::MetaPacket,
    flow_generator::error::{Error, Result},
    proto::flow_log,
    utils::bytes::read_u16_be,
};

const MQTT_TYPE_TBALE: &[&'static str] = &[
    "CONNECT",
    "CONNACK",
    "PUBLISH",
    "PUBACK",
    "PUBREC",
    "PUBREL",
    "PUBCOMP",
    "SUBSCRIBE",
    "SUBACK",
    "UNSUBSCRIBE",
    "UNSUBACK",
    "PINGREQ",
    "PINGRESP",
    "DISCONNECT",
    "AUTH",
];

#[derive(Debug, Default, Clone)]
pub struct MqttInfo {
    pub mqtt_type: String,
    // request
    pub req_msg_size: i32,
    pub proto_version: u8,
    pub client_id: String,

    // reponse
    pub resp_msg_size: i32,
}

impl MqttInfo {
    pub fn merge(&mut self, other: Self) {
        self.resp_msg_size = other.resp_msg_size;
    }

    pub fn check(&self) -> bool {
        if self.proto_version != 0
            && self.proto_version != 3
            && self.proto_version != 4
            && self.proto_version != 5
        {
            return false;
        }
        return self.mqtt_type.len() > 0 && self.mqtt_type.is_ascii();
    }
}

impl From<MqttInfo> for flow_log::MqttInfo {
    fn from(f: MqttInfo) -> Self {
        flow_log::MqttInfo {
            mqtt_type: f.mqtt_type,
            req_msg_size: f.req_msg_size,
            proto_version: f.proto_version as u32,
            client_id: f.client_id,
            resp_msg_size: f.resp_msg_size,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MqttLog {
    info: MqttInfo,
    msg_type: LogMessageType,
    status: L7ResponseStatus,
    reason_code: u8,
}

impl MqttLog {
    fn reset_logs(&mut self) {
        self.info.mqtt_type.clear();
        self.info.req_msg_size = -1;
        self.info.client_id.clear();
        self.status = L7ResponseStatus::Ok;
        self.reason_code = 0;
    }

    fn parse_mqtt_info(
        &mut self,
        payload: &[u8],
        direction: PacketDirection,
    ) -> Result<AppProtoHead> {
        let message_type = (payload[0] & 0xf0) >> 4;
        let message_flag = payload[0] & 0x0f;

        match message_type {
            0 => {
                return Err(Error::MqttLogParseFailed);
            }
            MQTT_PUBLISH => {}
            MQTT_PUBREL | MQTT_SUBSCRIBE | MQTT_UNSUBSCRIBE => {
                if message_flag != 2 {
                    return Err(Error::MqttLogParseFailed);
                }
            }
            _ => {
                if message_flag != 0 {
                    return Err(Error::MqttLogParseFailed);
                }
            }
        }

        self.info.mqtt_type = MQTT_TYPE_TBALE[(message_type - 1) as usize].to_string();
        let (var_len, payload_len) = parse_variable_length(&payload[1..])?;
        let offset = var_len + 1;

        match message_type {
            MQTT_CONNECT | MQTT_PUBLISH | MQTT_SUBSCRIBE | MQTT_UNSUBSCRIBE | MQTT_PINGREQ
            | MQTT_DISCONNECT => {
                self.msg_type = LogMessageType::Request;
                self.info.req_msg_size = payload_len;
            }
            MQTT_CONNACK | MQTT_PUBACK | MQTT_SUBACK | MQTT_UNSUBACK | MQTT_PINGRESP => {
                self.msg_type = LogMessageType::Response;
                self.info.resp_msg_size = payload_len;
            }
            _ => {
                self.msg_type = LogMessageType::Other;
            }
        }

        if message_type == MQTT_CONNECT {
            let (proto_ver, client_id) =
                parse_connect(&payload[offset..], Error::MqttLogParseFailed)?;
            self.info.proto_version = proto_ver;
            self.info.client_id = client_id;
        } else {
            self.parse_return_code(&payload[var_len..], direction, message_type)?;
        }

        Ok(AppProtoHead {
            proto: L7Protocol::Mqtt,
            msg_type: self.msg_type,
            status: self.status,
            code: self.reason_code as u16,
            rrt: 0,
        })
    }

    fn parse_return_code(
        &mut self,
        payload: &[u8],
        direction: PacketDirection,
        mqtt_type: u8,
    ) -> Result<()> {
        let status_code = get_status_code(
            payload,
            mqtt_type,
            self.info.proto_version,
            Error::MqttLogParseFailed,
        )?;

        if self.info.proto_version == 5 {
            match status_code {
                0 | 4 => self.status = L7ResponseStatus::Ok,
                MQTT_STATUS_FAILED_MIN..=MQTT_STATUS_FAILED_MAX => {
                    if direction == PacketDirection::ClientToServer {
                        self.status = L7ResponseStatus::ClientError;
                    } else {
                        self.status = L7ResponseStatus::ServerError
                    }
                }
                _ => return Err(Error::MqttLogParseFailed),
            }
        } else {
            if mqtt_type == MQTT_CONNACK {
                match status_code {
                    0 => self.status = L7ResponseStatus::Ok,
                    1..=3 => self.status = L7ResponseStatus::ServerError,
                    _ => self.status = L7ResponseStatus::ClientError,
                }
            }
        }

        self.reason_code = status_code;

        Ok(())
    }
}

impl L7LogParse for MqttLog {
    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
    ) -> Result<AppProtoHead> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }

        self.reset_logs();
        if payload.len() < MQTT_FIXED_HEADER_LEN {
            return Err(Error::MqttLogParseFailed);
        }
        self.parse_mqtt_info(payload, direction)
    }

    fn info(&self) -> AppProtoLogsInfo {
        AppProtoLogsInfo::Mqtt(self.info.clone())
    }
}

pub fn parse_variable_length(input: &[u8]) -> Result<(usize, i32), Error> {
    if input.len() < 1 {
        return Err(Error::MqttLogParseFailed);
    }

    let mut len = 0;
    let mut multiplier = 0;
    let mut bytes_var = 0;

    for &b in input.iter() {
        len += 1;
        bytes_var += ((b & 0x7f) as i32) << multiplier;

        if b & 0x80 != 0x80 {
            return Ok((len, bytes_var));
        }

        if len > MQTT_VAR_BYTES_MAX_LEN {
            return Err(Error::MqttLogParseFailed);
        }

        multiplier += 7;
    }
    Err(Error::MqttLogParseFailed)
}

fn with_mqtt(payload: &[u8], msg_len: u16) -> bool {
    if msg_len == 6 {
        if let Ok(payload_str) = std::str::from_utf8(&payload[2..8]) {
            payload_str.starts_with("MQIsdp")
        } else {
            return false;
        }
    } else if msg_len == 4 {
        if let Ok(payload_str) = std::str::from_utf8(&payload[2..6]) {
            payload_str.starts_with("MQTT")
        } else {
            return false;
        }
    } else {
        return false;
    }
}

pub fn parse_connect(input: &[u8], error: Error) -> Result<(u8, String), Error> {
    let mut offset = 0;
    let mut msg_len = read_u16_be(&input[offset..]);

    if !with_mqtt(&input[offset..], msg_len) {
        return Err(error);
    }

    offset += 2 + msg_len as usize;

    if input[offset] != 3 && input[offset] != 4 && input[offset] != 5 {
        return Err(error);
    }

    let proto_version = input[offset];

    offset += 4;

    msg_len = read_u16_be(&input[offset..]);

    offset += 2;

    let client_id = String::from_utf8_lossy(&input[offset..offset + msg_len as usize]).into_owned();

    Ok((proto_version, client_id))
}

pub fn get_status_code(
    input: &[u8],
    mqtt_type: u8,
    proto_version: u8,
    error: Error,
) -> Result<u8, Error> {
    /* 3 => MQTT 3.1 , 4 => MQTT 3.1.1 , 5 => MQTT 5.0 */
    if proto_version != 3 && proto_version != 4 && proto_version != 5 {
        return Ok(0);
    }

    let mut status_code = 0;

    if proto_version == 5 {
        match mqtt_type {
            MQTT_CONNACK | MQTT_PUBACK | MQTT_PUBREC | MQTT_PUBREL | MQTT_PUBCOMP => {
                status_code = input[2];
            }
            MQTT_DISCONNECT | MQTT_AUTH => {
                status_code = input[0];
            }
            _ => {
                status_code = 0;
            }
        }
    } else {
        if mqtt_type == MQTT_CONNACK {
            if input[0] != 2 || input[2] > 5 {
                return Err(error);
            }
            status_code = input[2];
        }
    }
    Ok(status_code)
}

pub fn mqtt_check_protocol(bitmap: &mut u128, packet: &MetaPacket) -> bool {
    if packet.lookup_key.proto != IpProtocol::Tcp {
        *bitmap &= !(1 << u8::from(L7Protocol::Mqtt));
        return false;
    }

    let payload = packet.get_l4_payload();
    if payload.is_none() {
        return false;
    }
    let payload = payload.unwrap();
    if payload.len() < MQTT_FIXED_HEADER_LEN {
        return false;
    }
    let mut mqtt = MqttLog::default();

    let ret = mqtt.parse_mqtt_info(payload, packet.direction);
    if ret.is_err() {
        return false;
    }

    return mqtt.info.check();
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{common::enums::PacketDirection, utils::test::Capture};

    const FILE_DIR: &str = "resources/test/flow_generator/mqtt";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut mqtt = MqttLog::default();
        let mut output: String = String::new();
        let mut bitmap = 0;
        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            packet.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };

            let _ = mqtt.parse(payload, packet.lookup_key.proto, packet.direction);
            let is_mqtt = mqtt_check_protocol(&mut bitmap, packet);
            output.push_str(&format!("{:?} is_mqtt: {}\r\n", mqtt.info, is_mqtt));
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![("mqtt_connect.pcap", "mqtt_connect.result")];

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
}
