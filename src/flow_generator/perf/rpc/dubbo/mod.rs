mod consts;
mod flow_dubbo;
mod flow_dubbo_log;

pub const PORT: u16 = 20880;

use consts::*;

use crate::{
    flow_generator::error::{Error, Result},
    utils::bytes::*,
};

#[derive(Debug, Default, PartialEq)]
struct DubboHeader {
    // Dubbo Header
    pub serial_id: u8,
    pub data_type: u8,
    pub status_code: u8,
    pub data_length: i32,
    pub request_id: i64,
}

impl DubboHeader {
    // Dubbo协议https://dubbo.apache.org/zh/blog/2018/10/05/dubbo-%E5%8D%8F%E8%AE%AE%E8%AF%A6%E8%A7%A3/#dubbo-%E5%8D%8F%E8%AE%AE
    // Dubbo协议帧
    // +-----------------------------------------------+
    // |       header           |       body           |
    // +---------------+---------------+---------------+
    // header格式
    // +------------------------------------------------------------------------------------------------------------+
    // | magic (16) | request and serialization flag (8) | response status (8) | request id (64) | body length (32) |
    // +------------------------------------------------------------------------------------------------------------+
    pub fn parse_headers(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() < DUBBO_HEADER_LEN {
            return Err(Error::DubboHeaderParseFailed);
        }
        if payload[0] != DUBBO_MAGIC_HIGH || payload[1] != DUBBO_MAGIC_LOW {
            return Err(Error::DubboHeaderParseFailed);
        }

        self.serial_id = payload[2] & 0x1f;
        self.data_type = payload[2] & 0x80;
        self.status_code = payload[3];
        self.request_id = read_u64_be(&payload[4..]) as i64;
        self.data_length = read_u32_be(&payload[12..]) as i32;
        Ok(())
    }
}

// 参考开源代码解析：https://github.com/apache/dubbo-go-hessian2/blob/master/decode.go#L289
pub fn get_req_param_len(tag: u8) -> Option<usize> {
    if (tag == BC_STRING_CHUNK || tag == BC_STRING)
        || (tag >= BC_STRING_DIRECT && tag <= STRING_DIRECT_MAX)
        || (tag >= 0x30 && tag <= 0x33)
    {
        return Some(tag as usize);
    }
    None
}
