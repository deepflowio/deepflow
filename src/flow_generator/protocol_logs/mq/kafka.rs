use super::super::{
    consts::{KAFKA_REQ_HEADER_LEN, KAFKA_RESP_HEADER_LEN},
    L7LogParse, LogMessageType,
};

use crate::flow_generator::error::{Error, Result};
use crate::proto::flow_log;
use crate::{
    common::enums::{IpProtocol, PacketDirection},
    utils::bytes::{read_u16_be, read_u32_be},
};

#[derive(Debug, Default, Clone)]
pub struct KafkaInfo {
    pub correlation_id: u32,

    // request
    pub req_msg_size: i32,
    pub api_version: u16,
    pub api_key: u16,
    pub client_id: String,

    // reponse
    pub resp_msg_size: i32,
}

impl KafkaInfo {
    pub fn merge(&mut self, other: Self) {
        self.resp_msg_size = other.resp_msg_size;
    }
}

impl From<KafkaInfo> for flow_log::KafkaInfo {
    fn from(f: KafkaInfo) -> Self {
        flow_log::KafkaInfo {
            correlation_id: f.correlation_id,
            req_msg_size: f.req_msg_size,
            api_version: f.api_version as u32,
            api_key: f.api_key as u32,
            client_id: f.client_id,
            resp_msg_size: f.resp_msg_size,
        }
    }
}

#[derive(Debug, Default)]
pub struct KafkaLog {
    info: KafkaInfo,
    msg_type: LogMessageType,
}

impl KafkaLog {
    fn reset_logs(&mut self) {
        self.info.correlation_id = 0;
        self.info.req_msg_size = -1;
        self.info.api_version = 0;
        self.info.api_key = 0;
        self.info.client_id = String::new();
        self.info.resp_msg_size = -1;
    }

    fn request(&mut self, payload: &[u8]) -> Result<()> {
        self.info.req_msg_size = read_u32_be(payload) as i32;
        let client_id_len = read_u16_be(&payload[12..]) as usize;
        if payload.len() < KAFKA_REQ_HEADER_LEN + client_id_len {
            return Err(Error::KafkaLogParseFailed);
        }

        self.info.api_key = read_u16_be(&payload[4..]);
        self.info.api_version = read_u16_be(&payload[6..]);
        self.info.correlation_id = read_u32_be(&payload[8..]);
        self.info.client_id =
            String::from_utf8_lossy(&payload[14..14 + client_id_len]).into_owned();
        Ok(())
    }

    fn response(&mut self, payload: &[u8]) -> Result<()> {
        self.info.resp_msg_size = read_u32_be(payload) as i32;
        self.info.correlation_id = read_u32_be(&payload[4..]);

        self.msg_type = LogMessageType::Response;

        Ok(())
    }
}

impl L7LogParse for KafkaLog {
    type Item = KafkaInfo;
    fn parse(
        &mut self,
        payload: impl AsRef<[u8]>,
        proto: IpProtocol,
        direction: PacketDirection,
    ) -> Result<()> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvalidIpProtocol);
        }
        self.reset_logs();
        let payload = payload.as_ref();
        if payload.len() < KAFKA_RESP_HEADER_LEN {
            return Err(Error::KafkaLogParseFailed);
        }
        match direction {
            PacketDirection::ClientToServer => self.request(payload),
            PacketDirection::ServerToClient => self.response(payload),
        }
    }

    fn info(&self) -> Self::Item {
        self.info.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{common::enums::PacketDirection, utils::test::Capture};

    const FILE_DIR: &str = "resources/test/flow_generator/kafka";

    fn run(name: &str) -> String {
        let capture = Capture::load_pcap(Path::new(FILE_DIR).join(name), None);
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut output: String = String::new();
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

            let mut kafka = KafkaLog::default();
            let _ = kafka.parse(payload, packet.lookup_key.proto, packet.direction);
            output.push_str(&format!("{:?}\r\n", kafka.info));
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![("kafka.pcap", "kafka.result")];

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
