use super::{KAFKA_REQ_HEADER_LEN, KAFKA_RESP_HEADER_LEN};

use crate::{
    common::{
        enums::{IpProtocol, PacketDirection},
        flow::L7Protocol,
        protocol_logs::{KafkaInfo, LogMessageType},
    },
    error::{Error, Result},
    utils::bytes,
};

const NO_KAFKA_LOG: &str = "no kafka log.";

#[derive(Debug, Default)]
struct KafkaLog {
    info: KafkaInfo,

    l7_proto: L7Protocol,
    msg_type: LogMessageType,
}

impl KafkaLog {
    fn new() -> Self {
        KafkaLog::default()
    }

    pub fn reset_logs(&mut self) {
        self.info.correlation_id = 0;
        self.info.req_msg_size = -1;
        self.info.api_version = 0;
        self.info.api_key = 0;
        self.info.client_id = String::new();
        self.info.resp_msg_size = -1;
    }

    fn get_log_data_special_info(self) {
        self.info;
    }

    fn request(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() < KAFKA_REQ_HEADER_LEN {
            return Err(Error::KafkaLogParse(NO_KAFKA_LOG.to_string()));
        }

        self.info.req_msg_size = bytes::read_u32_be(payload) as i32;
        let client_id_len = bytes::read_u16_be(&payload[12..]) as usize;
        if payload.len() < KAFKA_REQ_HEADER_LEN + client_id_len {
            return Err(Error::KafkaLogParse(NO_KAFKA_LOG.to_string()));
        }

        self.info.api_key = bytes::read_u16_be(&payload[4..]);
        self.info.api_version = bytes::read_u16_be(&payload[6..]);
        self.info.correlation_id = bytes::read_u32_be(&payload[8..]);
        self.info.client_id =
            String::from_utf8_lossy(&payload[14..14 + client_id_len]).into_owned();
        Ok(())
    }

    fn response(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() < KAFKA_RESP_HEADER_LEN {
            return Err(Error::KafkaLogParse(NO_KAFKA_LOG.to_string()));
        }

        self.info.resp_msg_size = bytes::read_u32_be(payload) as i32;
        self.info.correlation_id = bytes::read_u32_be(&payload[4..]);

        self.msg_type = LogMessageType::Response;

        Ok(())
    }

    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
    ) -> Result<()> {
        if proto != IpProtocol::Tcp {
            return Err(Error::KafkaLogParse(NO_KAFKA_LOG.to_string()));
        }

        self.reset_logs();
        match direction {
            PacketDirection::ClientToServer => self.request(payload),
            _ => self.response(payload),
        }
    }
}

#[cfg(test)]
mod test {
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
