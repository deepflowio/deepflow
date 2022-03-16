use super::decode::decode;

use crate::{
    common::{
        enums::{IpProtocol, PacketDirection},
        flow::L7Protocol,
        protocol_logs::{LogMessageType, RedisInfo},
    },
    error::{Error, Result},
};

#[derive(Debug, Default)]
struct RedisLog {
    info: RedisInfo,
    l7_proto: L7Protocol,
    msg_type: LogMessageType,
}

impl RedisLog {
    fn new() -> Self {
        RedisLog::default()
    }

    fn reset(&mut self) {
        *self = RedisLog::default();
    }

    pub fn get_log_data_special_info(self) -> RedisInfo {
        self.info
    }

    pub fn fill_request(&mut self, context: Vec<u8>) {
        self.info.request_type = match (&context).iter().position(|&x| x == b' ') {
            Some(i) if i > 0 => Vec::from(&context[..i]),
            _ => context.clone(),
        };
        self.msg_type = LogMessageType::Request;
        self.info.request = context;
    }

    pub fn fill_response(&mut self, context: Vec<u8>, error_response: bool) {
        self.msg_type = LogMessageType::Response;
        if context.is_empty() {
            return;
        }

        match context[0] {
            b'+' => self.info.status = context,
            b'-' if error_response => self.info.error = context,
            b'-' if !error_response => self.info.response = context,
            _ => self.info.response = context,
        }
    }

    pub fn parse(
        &mut self,
        payload: &[u8],
        protocol: IpProtocol,
        direction: PacketDirection,
    ) -> Result<()> {
        if protocol != IpProtocol::Tcp {
            let err_msg = format!("unsupport ip protocol {:?}", protocol);
            return Err(Error::RedisLogParse(err_msg));
        }
        self.reset();
        if let Some((context, _, error_response)) =
            decode(payload, direction == PacketDirection::ClientToServer)
        {
            match direction {
                PacketDirection::ClientToServer => self.fill_request(context),
                PacketDirection::ServerToClient => self.fill_response(context, error_response),
            };
            Ok(())
        } else {
            Err(Error::RedisLogParse("decode failed".to_string()))
        }
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{
        common::{enums::PacketDirection, meta_packet::MetaPacket},
        utils::test::load_pcap,
    };

    const FILE_DIR: &str = "resources/test/flow_generator/redis";

    fn run(name: &str) -> String {
        let pcap_file = Path::new(FILE_DIR).join(name);
        let mut packets: Vec<MetaPacket> = load_pcap(pcap_file, None);
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

            let mut redis = RedisLog::default();
            let _ = redis.parse(payload, packet.lookup_key.proto, packet.direction);
            output.push_str(&format!("{}\r\n", redis.info));
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("redis.pcap", "redis.result"),
            ("redis-error.pcap", "redis-error.result"),
            ("redis-debug.pcap", "redis-debug.result"),
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
}
