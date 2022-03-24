use super::{consts::*, get_req_param_len, DubboHeader};

use crate::{
    common::{
        enums::{IpProtocol, PacketDirection},
        flow::L7Protocol,
        protocol_logs::{DubboInfo, LogMessageType},
    },
    flow_generator::error::{Error, Result},
};

#[derive(Debug, Default)]
struct DubboLog {
    pub info: DubboInfo,

    status_code: u8,
    l7_proto: L7Protocol,
    msg_type: LogMessageType,
}

impl DubboLog {
    fn new() -> Self {
        DubboLog::default()
    }

    pub fn reset_logs(&mut self) {
        self.info.serial_id = 0;
        self.info.data_type = 0;
        self.info.request_id = 0;
        self.info.req_msg_size = -1;
        self.info.dubbo_version = String::new();
        self.info.service_name = String::new();
        self.info.service_version = String::new();
        self.info.method_name = String::new();
        self.info.resp_msg_size = -1;
    }

    fn get_log_data_special_info(self) {
        self.info;
    }

    // 尽力而为的去解析Dubbo请求中Body各参数
    fn get_req_body_info(&mut self, payload: &[u8]) {
        let mut n = BODY_PARAM_MIN;
        let mut para_index = 1;
        let mut para_tag = payload[0];
        let payload_len = payload.len();

        while n < BODY_PARAM_MAX {
            let para_len = match get_req_param_len(para_tag) {
                Some(len) if payload_len >= para_index + len => len,
                _ => return,
            };

            match n {
                BODY_PARAM_DUBBO_VERSION => {
                    self.info.dubbo_version =
                        String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                            .into_owned()
                }

                BODY_PARAM_SERVICE_NAME => {
                    self.info.service_name =
                        String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                            .into_owned();
                }

                BODY_PARAM_SERVICE_VERSION => {
                    self.info.service_version =
                        String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                            .into_owned();
                }

                BODY_PARAM_METHOD_NAME => {
                    self.info.method_name =
                        String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                            .into_owned();
                }
                _ => return,
            }

            para_index += para_len;
            if payload_len <= para_index {
                return;
            }
            para_tag = payload[para_index];
            para_index += 1;
            n += 1;
        }
    }

    fn request(&mut self, payload: &[u8], dubbo_header: &DubboHeader) {
        self.msg_type = LogMessageType::Request;

        self.info.data_type = dubbo_header.data_type;
        self.info.req_msg_size = dubbo_header.data_length;
        self.info.serial_id = dubbo_header.serial_id;
        self.info.request_id = dubbo_header.request_id;

        self.get_req_body_info(&payload[DUBBO_HEADER_LEN..]);
    }

    fn response(&mut self, dubbo_header: &DubboHeader) {
        self.msg_type = LogMessageType::Response;

        self.info.data_type = dubbo_header.data_type;
        self.info.resp_msg_size = dubbo_header.data_length;
        self.info.serial_id = dubbo_header.serial_id;
        self.info.request_id = dubbo_header.request_id;
        self.status_code = dubbo_header.status_code;
    }

    fn parse(
        &mut self,
        payload: &[u8],
        proto: IpProtocol,
        direction: PacketDirection,
    ) -> Result<()> {
        if proto != IpProtocol::Tcp {
            return Err(Error::InvaildIpProtocol);
        }
        self.reset_logs();

        let mut dubbo_header = DubboHeader::default();
        dubbo_header.parse_headers(payload)?;

        match direction {
            PacketDirection::ClientToServer => {
                self.request(payload, &dubbo_header);
            }
            PacketDirection::ServerToClient => {
                self.response(&dubbo_header);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{common::enums::PacketDirection, utils::test::Capture};

    const FILE_DIR: &str = "resources/test/flow_generator/dubbo";

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

            let mut dubbo = DubboLog::default();
            let _ = dubbo.parse(payload, packet.lookup_key.proto, packet.direction);
            output.push_str(&format!("{:?}\r\n", dubbo.info));
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![("dubbo_hessian2.pcap", "dubbo_hessian.result")];

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
