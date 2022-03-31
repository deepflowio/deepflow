mod consts;
mod flow_mysql;
mod flow_mysql_log;

pub use flow_mysql::MysqlPerfData;
pub const PORT: u16 = 3306;

use self::consts::*;

use crate::{
    common::{enums::PacketDirection, flow::L7Protocol, protocol_logs::LogMessageType},
    utils::bytes,
};

#[derive(Debug, Default)]
struct Header {
    length: u32,
    number: u8,
}

impl Header {
    fn decode(&mut self, payload: &[u8]) -> usize {
        if payload.len() < 5 {
            return 0;
        }
        let len = bytes::read_u32_le(payload) & 0xffffff;
        if payload[HEADER_LEN + RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_OK
            || payload[HEADER_LEN + RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_ERR
            || payload[HEADER_LEN + RESPONSE_CODE_OFFSET] == MYSQL_RESPONSE_CODE_EOF
            || payload[NUMBER_OFFSET] == 0
        {
            self.length = len;
            self.number = payload[NUMBER_OFFSET];
            return HEADER_LEN;
        }
        let offset = len as usize + HEADER_LEN;
        if offset > payload.len() {
            return 0;
        }
        offset + self.decode(&payload[offset..])
    }

    fn check(
        &self,
        direction: PacketDirection,
        offset: usize,
        payload: &[u8],
        l7_proto: L7Protocol,
    ) -> Option<LogMessageType> {
        if offset > payload.len() || self.length == 0 {
            return None;
        }
        if self.number != 0 && l7_proto == L7Protocol::Unknown {
            return None;
        }

        match direction {
            PacketDirection::ServerToClient if self.number == 0 => {
                let payload = &payload[offset..];
                if payload.len() < PROTOCOL_VERSION_LEN {
                    return None;
                }
                let protocol_version = payload[PROTOCOL_VERSION_OFFSET];
                let index = payload[SERVER_VERSION_OFFSET..]
                    .iter()
                    .position(|&x| x == SERVER_VERSION_EOF)?;
                if index != 0 && protocol_version == PROTOCOL_VERSION {
                    Some(LogMessageType::Other)
                } else {
                    None
                }
            }
            PacketDirection::ServerToClient => Some(LogMessageType::Response),
            PacketDirection::ClientToServer if self.number == 0 => Some(LogMessageType::Request),
            _ => None,
        }
    }
}
