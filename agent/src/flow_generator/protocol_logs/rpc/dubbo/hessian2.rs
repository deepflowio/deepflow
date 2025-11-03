/*
 * Copyright (c) 2025 Yunshan Networks
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

use std::cell::OnceCell;
use std::collections::HashMap;
use std::fmt::Display;

use nom::FindSubstring;
use regex::Regex;

use super::consts::*;
use super::{DubboInfo, BODY_PARAM_MAX, BODY_PARAM_MIN};
use crate::config::handler::{L7LogDynamicConfig, TraceType};

cfg_if::cfg_if! {
if #[cfg(feature = "enterprise")] {
        use crate::common::flow::{L7Protocol, PacketDirection, L7ProtocolEnum};
        use crate::flow_generator::protocol_logs::pb_adapter::{KeyVal, MetricKeyVal};
        use enterprise_utils::l7::custom_policy::{
            custom_field_policy::ExtraField,
            enums::FieldType,
        };
    }
}

#[derive(Debug)]
enum HessianValue {
    Null,
    Bool(bool),
    Int(i32),
    Long(i64),
    DateTime(i64),
    Double(f64),
    Binary(Vec<u8>),
    String(String),
    Map(HashMap<String, HessianValue>),
}

impl Display for HessianValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HessianValue::Null => write!(f, ""),
            HessianValue::Bool(b) => write!(f, "{}", b),
            HessianValue::Int(i) => write!(f, "{}", i),
            HessianValue::Long(l) => write!(f, "{}", l),
            HessianValue::DateTime(d) => write!(f, "{}", d),
            HessianValue::Double(d) => write!(f, "{}", d),
            HessianValue::Binary(b) => write!(f, "{}", String::from_utf8_lossy(b)),
            HessianValue::String(s) => write!(f, "{}", s),
            HessianValue::Map(m) => write!(f, "{:?}", m),
        }
    }
}

#[derive(Default)]
struct Hessian2Decoder {
    class_field_info: Vec<Vec<String>>,
}

impl Hessian2Decoder {
    thread_local! {
        static DUBBO_ARG_TYPES_REGEX: OnceCell<Regex> = OnceCell::new();
    }

    // 返回具体值和读了多少长度，注意 长度返回 1 表示读取了 start 索引
    fn decode_field(&mut self, bytes: &[u8], start: usize) -> (Option<HessianValue>, usize) {
        if start >= bytes.len() {
            return (None, 0);
        }

        match bytes[start] {
            BC_END => (None, 1),
            // 实际值就是 null，即未初始化，不要给 None，因为可能解出 map key 但 value = null
            BC_NULL => (Some(HessianValue::Null), 1),
            BC_TRUE => (Some(HessianValue::Bool(true)), 1),
            BC_FALSE => (Some(HessianValue::Bool(false)), 1),
            BC_REF => {
                // ref 意为通过索引号获取一个指向 list/map 的指针
                let (_, len) = Self::decode_i32(bytes, start);
                (None, len)
            }
            // int
            0x80..=0xbf | 0xc0..=0xcf | 0xd0..=0xd7 | BC_INT => {
                let (value, len) = Self::decode_i32(bytes, start);
                (Some(HessianValue::Int(value)), len)
            }
            // long
            0xd8..=0xef | 0xf0..=0xff | 0x38..=0x3f | BC_LONG_INT | BC_LONG => {
                let (value, len) = Self::decode_i64(bytes, start);
                (Some(HessianValue::Long(value)), len)
            }
            // date
            BC_DATE | BC_DATE_MINUTE => {
                let (value, len) = Self::decode_datetime(bytes, start);
                (Some(HessianValue::DateTime(value)), len)
            }
            // double
            BC_DOUBLE_ZERO | BC_DOUBLE_ONE | BC_DOUBLE_BYTE | BC_DOUBLE_SHORT | BC_DOUBLE_MILL
            | BC_DOUBLE => {
                let (value, len) = Self::decode_f64(bytes, start);
                (Some(HessianValue::Double(value)), len)
            }
            // binary
            BC_BINARY_DIRECT..=INT_DIRECT_MAX
            | BC_BINARY_SHORT..=0x37
            | BC_BINARY_CHUNK
            | BC_BINARY => {
                let (value, len) = Self::decode_binary(bytes, start);
                (Some(HessianValue::Binary(value)), len)
            }
            // string
            BC_STRING_SHORT..=BC_STRING_SHORT_MAX
            | BC_STRING_DIRECT..=STRING_DIRECT_MAX
            | BC_STRING_CHUNK
            | BC_STRING => {
                if let (Some(value), len) = Self::decode_string(bytes, start) {
                    (Some(HessianValue::String(value)), len)
                } else {
                    // tag 表示为 string 但无法读出合法的 string，说明数据有异常，剩下的数据也不需要继续读了
                    (None, bytes.len())
                }
            }
            // list: 没有实用意义，因为无法按 key 提取数据，但要跳过 list 的长度继续解析
            BC_LIST_DIRECT..=0x77
            | BC_LIST_DIRECT_UNTYPED..=0x7f
            | BC_LIST_FIXED
            | BC_LIST_VARIABLE
            | BC_LIST_FIXED_UNTYPED
            | BC_LIST_VARIABLE_UNTYPED => (None, self.decode_list(bytes, start)),
            // hashmap
            BC_MAP | BC_MAP_UNTYPED => {
                let (value, len) = self.decode_map(bytes, start);
                (Some(HessianValue::Map(value)), len)
            }
            // object，只能处理为 hashmap
            BC_OBJECT_DEF | BC_OBJECT | BC_OBJECT_DIRECT..=BC_OBJECT_DIRECT_MAX => {
                let (value, len) = self.decode_obj(bytes, start);
                (Some(HessianValue::Map(value)), len)
            }
            _ => (None, bytes.len()), // 如果不符合任何一种，表示这个 tag 没有意义，直接丢弃剩余所有数据
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/map.go#L240
    fn decode_map(
        &mut self,
        payload: &[u8],
        index: usize,
    ) -> (HashMap<String, HessianValue>, usize) {
        let mut tag = payload[index];
        let mut start = index + 1;
        let mut map = HashMap::new();
        if start >= payload.len() {
            return (map, 0);
        }
        if tag == BC_MAP {
            // 即使是 typedmap(标示了类型的 map)，也只能处理成 hashmap<string, string>, 这里忽略实际类型，只跳过读取长度
            let (_, len) = Self::decode_string(payload, start);
            if len == 0 {
                let (_, len) = Self::decode_i32(payload, start);
                start += len;
            }
        }
        while tag != BC_END {
            let (key, len) = self.decode_field(payload, start);
            start += len;
            let (value, len) = self.decode_field(payload, start);
            start += len;
            match (key, value) {
                (Some(HessianValue::String(k)), Some(v)) => map.insert(k, v),
                _ => None,
            };
            if start >= payload.len() {
                break;
            }
            tag = payload[start]
        }
        // 读取完后这里会丢弃下一个 byte，所以 +1
        // ref: https://github.com/apache/dubbo-go-hessian2/blob/master/map.go#L320
        (map, start - index + 1)
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/list.go#L280
    // 注意：这里 list 具体的值没有用，只是为了解出要读多少 len
    fn decode_list(&mut self, payload: &[u8], index: usize) -> usize {
        let tag = payload[index];
        let mut start = index + 1;
        if start >= payload.len() {
            return 0;
        }
        let arr_len = match tag {
            BC_LIST_FIXED => {
                let (_, len) = Self::decode_string(payload, start);
                start += len;
                if start >= payload.len() {
                    return 0;
                }
                let (arr_len, len) = Self::decode_i32(payload, start);
                start += len;
                arr_len as usize
            }
            BC_LIST_VARIABLE => {
                let (_, len) = Self::decode_string(payload, start);
                start += len;
                if start >= payload.len() {
                    return start - index;
                }
                // 遇到这种情况意味着是未知长度 list，内容一直到第一个 BC_END 为止（也有可能剩下的所有内容都是这个 list）
                return payload[start..]
                    .iter()
                    .position(|&b| b == BC_END)
                    .unwrap_or(payload.len() - 1)
                    + 1
                    - index;
            }
            BC_LIST_FIXED_TYPED_LEN_TAG_MIN..=BC_LIST_FIXED_TYPED_LEN_TAG_MAX => {
                let (_, len) = Self::decode_string(payload, start);
                start += len;
                tag.overflowing_sub(BC_LIST_FIXED_TYPED_LEN_TAG_MIN).0 as usize
            }
            BC_LIST_FIXED_UNTYPED => {
                let (arr_len, len) = Self::decode_i32(payload, start);
                start += len;
                arr_len as usize
            }
            BC_LIST_VARIABLE_UNTYPED => {
                return payload[start..]
                    .iter()
                    .position(|&b| b == BC_END)
                    .unwrap_or(payload.len() - 1)
                    + 1
                    - index;
            }
            BC_LIST_FIXED_UNTYPED_LEN_TAG_MIN..=BC_LIST_FIXED_UNTYPED_LEN_TAG_MAX => {
                tag.overflowing_sub(BC_LIST_FIXED_UNTYPED_LEN_TAG_MIN).0 as usize
            }
            _ => 0,
        };
        for _ in 0..arr_len {
            if start >= payload.len() {
                break;
            }
            let (_, len) = self.decode_field(payload, start);
            start += len;
        }
        start - index
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/object.go#L567
    fn decode_obj(
        &mut self,
        payload: &[u8],
        index: usize,
    ) -> (HashMap<String, HessianValue>, usize) {
        let tag = payload[index];
        let mut start = index + 1;
        let mut object_map = HashMap::new();
        // object 类型的消息一般是 BC_OBJECT_DEF 携带对象定义，紧接着一个 BC_OBJECT/BC_OBJECT_DIRECT 携带实例数据
        match tag {
            BC_OBJECT_DEF => {
                let (_, len) = Self::decode_string(payload, start);
                start += len;
                if start >= payload.len() {
                    return (object_map, 0);
                }
                let (field_num, len) = Self::decode_i32(payload, start);
                start += len;
                let mut field_list = Vec::with_capacity(field_num as usize);
                for _ in 0..field_num {
                    if start >= payload.len() {
                        break;
                    }
                    if let (Some(field_name), len) = Self::decode_string(payload, start) {
                        start += len;
                        field_list.push(field_name);
                    } else {
                        break;
                    }
                }
                // 需要先把 BC_OBJECT_DEF 的解析加入索引中
                self.class_field_info.push(field_list);
                // 这里会跳到 BC_OBJECT 继续解析
                let (value, len) = self.decode_field(payload, start);
                match value {
                    Some(HessianValue::Map(map)) => {
                        return (map, start + len - index);
                    }
                    _ => {
                        return (object_map, start + len - index);
                    }
                }
            }
            BC_OBJECT | BC_OBJECT_DIRECT..=BC_OBJECT_DIRECT_MAX => {
                let class_index = if tag == BC_OBJECT {
                    let (idx, len) = Self::decode_i32(payload, start);
                    start += len;
                    idx as usize
                } else {
                    tag.overflowing_sub(BC_OBJECT_DIRECT).0 as usize
                };
                // 无论 object type 是什么类型，都需要解析为 hashmap (field_name => value)
                // 但如果是 java 内置类型或自定义类型，都无法解析，如果遇到了会导致后续解析失败
                if class_index >= self.class_field_info.len() {
                    return (object_map, 0);
                }
                let field_list = self.class_field_info[class_index].clone();
                for i in 0..field_list.len() {
                    let field_name = &field_list[i];
                    let (value, len) = self.decode_field(payload, start);
                    if value.is_some() {
                        object_map.insert(field_name.to_string(), value.unwrap());
                    }
                    start += len;
                }
                (object_map, start - index)
            }
            _ => (object_map, 0),
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/int.go#L60
    fn decode_i32(payload: &[u8], index: usize) -> (i32, usize) {
        let tag = payload[index];
        match tag {
            0x80..=0xbf => ((tag.overflowing_sub(BC_INT_ZERO).0) as i32, 1),
            0xc0..=0xcf if index + 1 < payload.len() => (
                u16::from_be_bytes([tag.overflowing_sub(BC_INT_BYTE_ZERO).0, payload[index + 1]])
                    as i32,
                2,
            ),
            0xd0..=0xd7 if index + 2 < payload.len() => {
                let mut buf = [
                    0,
                    tag.overflowing_sub(BC_INT_SHORT_ZERO).0,
                    payload[index + 1],
                    payload[index + 2],
                ];
                if buf[1] & 0x80 != 0 {
                    buf[0] = 0xff;
                }
                (u32::from_be_bytes(buf) as i32, 3)
            }
            BC_INT if index + 4 < payload.len() => (
                i32::from_be_bytes(payload[index + 1..index + 5].try_into().unwrap_or_default()),
                5,
            ),
            _ => (0, 0),
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/long.go#L63
    fn decode_i64(payload: &[u8], index: usize) -> (i64, usize) {
        let tag = payload[index];
        match tag {
            0xd8..=0xef => ((tag.overflowing_sub(BC_LONG_ZERO).0) as i64, 1),
            0xf0..=0xff if index + 1 < payload.len() => {
                let buf = [tag.overflowing_sub(BC_LONG_BYTE_ZERO).0, payload[index + 1]];
                (u16::from_be_bytes(buf) as i64, 2)
            }
            0x38..=0x3f if index + 2 < payload.len() => {
                let mut buf = [
                    0,
                    tag.overflowing_sub(BC_LONG_SHORT_ZERO).0,
                    payload[index + 1],
                    payload[index + 2],
                ];
                if buf[1] & 0x80 != 0 {
                    buf[0] = 0xff;
                }
                (u32::from_be_bytes(buf) as i64, 3)
            }
            BC_LONG_INT if index + 4 < payload.len() => (
                i32::from_be_bytes(payload[index + 1..index + 5].try_into().unwrap_or_default())
                    as i64,
                5,
            ),
            BC_LONG if index + 8 < payload.len() => (
                i64::from_be_bytes(payload[index + 1..index + 9].try_into().unwrap_or_default()),
                9,
            ),
            _ => (0, 0),
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/date.go#L60
    fn decode_datetime(payload: &[u8], index: usize) -> (i64, usize) {
        let tag = payload[index];
        match tag {
            BC_DATE if index + 8 < payload.len() => (
                u64::from_be_bytes(payload[index + 1..index + 9].try_into().unwrap_or_default())
                    as i64,
                9,
            ),
            BC_DATE_MINUTE if index + 4 < payload.len() => (
                (u32::from_be_bytes(payload[index + 1..index + 5].try_into().unwrap_or_default())
                    * 60) as i64,
                5,
            ),
            _ => (0, 0),
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/double.go#L109
    fn decode_f64(payload: &[u8], index: usize) -> (f64, usize) {
        let tag = payload[index];
        match tag {
            BC_DOUBLE_ZERO => (0.0, 1),
            BC_DOUBLE_ONE => (1.0, 1),
            BC_DOUBLE_BYTE if index + 1 < payload.len() => (
                u8::from_be_bytes(payload[index + 1..index + 2].try_into().unwrap_or_default())
                    as f64,
                2,
            ),
            BC_DOUBLE_SHORT if index + 2 < payload.len() => (
                u16::from_be_bytes(payload[index + 1..index + 3].try_into().unwrap_or_default())
                    as f64,
                3,
            ),
            BC_DOUBLE_MILL if index + 4 < payload.len() => (
                u32::from_be_bytes(payload[index + 1..index + 5].try_into().unwrap_or_default())
                    as f64,
                5,
            ),
            BC_DOUBLE if index + 8 < payload.len() => (
                f64::from_be_bytes(payload[index + 1..index + 9].try_into().unwrap_or_default()),
                9,
            ),
            _ => (0.0, 0),
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/binary.go#L124
    fn decode_binary(payload: &[u8], index: usize) -> (Vec<u8>, usize) {
        let mut result = Vec::new();
        let mut start = index;
        let mut tag = payload[start];
        loop {
            let len = match tag {
                BC_BINARY_DIRECT..=INT_DIRECT_MAX => {
                    start += 1;
                    (tag.overflowing_sub(BC_BINARY_DIRECT).0) as usize
                }
                BC_BINARY_SHORT..=0x37 if start + 1 < payload.len() => {
                    start += 2;
                    ((tag.overflowing_sub(BC_BINARY_SHORT).0) as usize)
                        << 8 + payload[start - 1] as usize
                }
                BC_BINARY_CHUNK | BC_BINARY if start + 2 < payload.len() => {
                    start += 3;
                    ((payload[start - 2] as usize) << 8) + payload[start - 1] as usize
                }
                _ => return (result, 0),
            };
            if start >= payload.len() || start + len > payload.len() {
                break;
            }
            result.extend_from_slice(&payload[start..start + len]);
            start += len;
            if tag != BC_BINARY_CHUNK {
                // tag == BC_BINARY_CHUNK, continue to read
                break;
            }
            if start >= payload.len() {
                break;
            }
            tag = payload[start];
        }
        return (result, start - index);
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/string.go#L204
    fn decode_string(payload: &[u8], index: usize) -> (Option<String>, usize) {
        let mut result = Vec::new();
        let mut start = index;
        let mut tag = payload[start];
        loop {
            let len = match tag {
                BC_STRING_DIRECT..=STRING_DIRECT_MAX => {
                    start += 1;
                    // 这里应该是 tag-BC_STRNG_DIRECT，但 BC_STRING_DIRECT 刚好等于 0x00，故省略
                    tag as usize
                }
                BC_STRING_SHORT..=BC_STRING_SHORT_MAX if start + 1 < payload.len() => {
                    start += 2;
                    (((payload[start - 2] - BC_STRING_SHORT) as usize) << 8)
                        + payload[start - 1] as usize
                }
                BC_STRING_CHUNK | BC_STRING if start + 2 < payload.len() => {
                    start += 3;
                    ((payload[start - 2] as usize) << 8) + payload[start - 1] as usize
                }
                _ => return (None, 0),
            };
            if start >= payload.len() || start + len > payload.len() {
                break;
            }
            result.extend_from_slice(&payload[start..start + len]);
            start += len;
            if tag != BC_STRING_CHUNK {
                // 非 BC_STRING_CHUNK 直接跳出，BC_STRING_CHUNK 则继续读下一个 CHUNK
                break;
            }
            if start >= payload.len() {
                break;
            }
            tag = payload[start];
        }
        if is_invalid_ascii(&result, 0, result.len()) {
            return (None, 0);
        }
        return (
            Some(String::from_utf8_lossy(&result).into_owned()),
            start - index,
        );
    }

    #[cfg(feature = "enterprise")]
    fn parse_args(
        &mut self,
        payload: &[u8],
        start: usize,
        direction: PacketDirection,
    ) -> (Option<HashMap<String, HessianValue>>, usize) {
        match direction {
            PacketDirection::ClientToServer => self.parse_req_args(payload, start),
            PacketDirection::ServerToClient => self.parse_resp_args(payload, start),
        }
    }

    fn parse_req_args(
        &mut self,
        payload: &[u8],
        start: usize,
    ) -> (Option<HashMap<String, HessianValue>>, usize) {
        let payload_len = payload.len();
        let mut start_index = start;
        let mut args_count: u8;
        let read_len = 0;
        // there're several community implements for dubbo args encoding:
        // offcial: | dubboVersion | serviceName | serviceVersion | method        | argTypes | args | attachments |
        // dubbox:  | dubboVersion | serviceName | serviceVersion | method | 0x8f | argTypes | args | attachments |
        // here, we try to adapt those 2 implements to find real argTypes
        loop {
            let (value, read_len) = self.decode_field(&payload, start_index);
            if start_index + read_len > payload_len {
                return (None, start);
            }
            start_index += read_len;
            args_count = match value {
                Some(HessianValue::String(arg_types)) => Self::DUBBO_ARG_TYPES_REGEX.with(|r| {
                    r.get_or_init(|| Regex::new(DUBBO_ARG_TYPES_REGEX_STR).unwrap())
                        .find_iter(&arg_types)
                        .count() as u8
                }),
                // skip known 0x8f between | method | argTypes |
                Some(HessianValue::Int(_)) => continue,
                _ => return (None, start_index),
            };
            break;
        }

        let mut args = HashMap::new();
        while args_count > 0 {
            let (value, read_len) = self.decode_field(&payload, start_index);
            if start_index + read_len > payload_len {
                return (None, start_index);
            }
            start_index += read_len;
            match value {
                Some(HessianValue::Map(map)) => {
                    args.extend(map);
                }
                _ => (),
            }
            args_count -= 1;
        }
        log::debug!(
            "read hessian payload end, final index: {}, payload len: {}",
            start + read_len,
            payload.len()
        );
        return (Some(args), start_index);
    }

    fn parse_resp_args(
        &mut self,
        payload: &[u8],
        start: usize,
    ) -> (Option<HashMap<String, HessianValue>>, usize) {
        let payload_len = payload.len();
        let mut start_index = start;
        let (response_type, read_len) = self.decode_field(&payload, start_index);
        if start_index + read_len > payload_len {
            return (None, start_index);
        }
        start_index += read_len;
        match response_type {
            Some(HessianValue::Int(RESPONSE_WITH_EXCEPTION))
            | Some(HessianValue::Int(RESPONSE_WITH_EXCEPTION_WITH_ATTACHMENTS)) => {
                // can extract exception message here but not required
                let (_, read_len) = self.decode_field(&payload, start_index);
                start_index += read_len;
                (None, start_index)
            }
            Some(HessianValue::Int(RESPONSE_VALUE))
            | Some(HessianValue::Int(RESPONSE_VALUE_WITH_ATTACHMENTS)) => {
                let (response_object, read_len) = self.decode_field(&payload, start_index);
                start_index += read_len;
                if let Some(HessianValue::Map(map)) = response_object {
                    (Some(map), start_index)
                } else {
                    (None, start_index)
                }
            }
            Some(HessianValue::Int(RESPONSE_NULL_VALUE)) => (None, payload_len), // with attachments, directly read to end
            _ => (None, start_index),
        }
    }

    fn parse_attachments(
        &mut self,
        payload: &[u8],
        start: usize,
    ) -> (Option<HashMap<String, HessianValue>>, usize) {
        let (value, read_len) = self.decode_field(&payload, start);
        match value {
            Some(HessianValue::Map(attachments)) => (Some(attachments), start + read_len),
            _ => (None, start),
        }
    }

    // fuzzy search value by key in req/resp, actually, we can only fuzzy search value in map<string, field>
    // 在 req/resp 中模糊搜索指定的 key 对应的 value，实际上这里只能在 map<string, field> 中搜索
    fn search_key(
        &mut self,
        payload: &[u8],
        key: &str,
        start_index: usize,
    ) -> Option<HessianValue> {
        let mut start = start_index;
        let key_bytes = key.as_bytes();
        while start < payload.len() {
            if start >= payload.len() {
                break;
            }
            // 这里直接用 eq_ignore_ascii_case 搜索即可，在 process_hessian_value 中会有 field.match 按真实配置校验
            let Some(index) = (&payload[start..])
                .windows(key_bytes.len())
                .position(|w| w.eq_ignore_ascii_case(key_bytes))
            else {
                break;
            };
            // 反向校验长度，decode_string 的逆实现，一般 key 的长度有限，这里需要避免 key 误匹配
            // length validation, reverse implement of decode_string, usually we got a limited length of key, and we need to avoid mismatch
            let key_len_validate = match key.len() {
                len if len <= STRING_DIRECT_MAX_LEN && index > 0 => {
                    payload[start + index - 1] as usize
                }
                len if len <= STRING_SHORT_MAX_LEN && index > 1 => {
                    (((payload[start + index - 2] - BC_STRING_SHORT) as usize) << 8)
                        + payload[start + index - 1] as usize
                }
                len if len <= STRING_MAX_LEN && index > 1 => {
                    ((payload[start + index - 2] as usize) << 8)
                        + payload[start + index - 1] as usize
                }
                _ => 0,
            };

            // 可能误匹配了子串，跳过长度继续搜索
            // maybe mismatch for substring, skip and search next
            if key.len() != key_len_validate {
                start += index + key.len();
                continue;
            }

            // can not guarantee the type of value, so just decoded to hessian value then to_string()
            // 这里没法保证具体的值是什么类型，都解为 hessian value 然后 to_string()
            if let (Some(context), _) = self.decode_field(payload, start + index + key.len()) {
                return Some(context);
            }
            start += index + key.len();
        }
        None
    }
}

fn is_invalid_ascii(payload: &[u8], start: usize, end: usize) -> bool {
    let end = payload.len().min(end);
    for index in start..end {
        if !payload[index].is_ascii() {
            return true;
        }
    }
    false
}

fn lookup_str(payload: &[u8], trace_type: &TraceType) -> Option<String> {
    let tag = match trace_type {
        TraceType::Sw3 | TraceType::Sw8 | TraceType::CloudWise | TraceType::Customize(_) => {
            trace_type.as_str()
        }
        _ => return None,
    };

    let mut start = 0;
    while start < payload.len() {
        if !payload[start].is_ascii() {
            break;
        }
        let Some(index) = (&payload[start..]).find_substring(tag) else {
            break;
        };
        // 注意这里tag长度不会超过256
        if index == 0 || tag.len() != payload[start + index - 1] as usize {
            start += index + tag.len();
            continue;
        }

        if let (Some(context), _) =
            Hessian2Decoder::decode_string(payload, start + index + tag.len())
        {
            return Some(context);
        }
        start += index + tag.len();
    }
    return None;
}

// 注意 dubbo trace id 解析是区分大小写的
fn decode_trace_ids(payload: &[u8], trace_type: &TraceType, info: &mut DubboInfo) {
    if let Some(trace_id) = lookup_str(payload, trace_type) {
        info.add_trace_id(trace_id, trace_type);
    }
}

fn decode_span_id(payload: &[u8], trace_type: &TraceType, info: &mut DubboInfo) {
    if let Some(span_id) = lookup_str(payload, trace_type) {
        info.set_span_id(span_id, trace_type);
    }
}

// 参考开源代码解析：https://github.com/apache/dubbo-go-hessian2/blob/master/decode.go#L289
// https://github.com/apache/dubbo-go-hessian2/blob/v2.0.0/string.go#L169
// 返回offset和数据length
fn get_req_param_len(payload: &[u8]) -> (usize, usize) {
    let tag = payload[0];
    match tag {
        BC_STRING_DIRECT..=STRING_DIRECT_MAX => (1, tag as usize),
        BC_STRING_SHORT..=BC_STRING_SHORT_MAX if payload.len() > 2 => {
            (2, ((tag as usize - 0x30) << 8) + payload[1] as usize)
        }
        BC_STRING_CHUNK | BC_STRING if payload.len() > 3 => {
            (3, ((payload[1] as usize) << 8) + payload[2] as usize)
        }
        _ => (0, 0),
    }
}

// 尽力而为的去解析Dubbo请求中Body各参数
// 解析逻辑：https://github.com/apache/dubbo-go/blob/v3.3.0/protocol/dubbo/impl/hessian.go
pub fn get_req_body_info(
    config: &L7LogDynamicConfig,
    payload: &[u8],
    info: &mut DubboInfo,
    #[cfg(feature = "enterprise")] direction: PacketDirection,
    #[cfg(feature = "enterprise")] port: u16,
) {
    let mut n = BODY_PARAM_MIN;
    let mut para_index = 0;
    let payload_len = payload.len();

    while n < BODY_PARAM_MAX && para_index < payload_len {
        let (offset, para_len) = get_req_param_len(&payload[para_index..]);
        para_index += offset;
        if para_len == 0 || para_len + para_index > payload_len {
            return;
        }

        match n {
            BODY_PARAM_DUBBO_VERSION => {
                info.dubbo_version =
                    String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                        .into_owned()
            }
            BODY_PARAM_SERVICE_NAME => {
                info.service_name =
                    String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                        .into_owned();
            }
            BODY_PARAM_SERVICE_VERSION => {
                info.service_version =
                    String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                        .into_owned();
            }
            BODY_PARAM_METHOD_NAME => {
                info.method_name =
                    String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                        .into_owned();
            }
            _ => return,
        }

        para_index += para_len;
        if payload_len <= para_index {
            return;
        }
        n += 1;
    }

    if config.trace_types.is_empty() || para_index >= payload.len() {
        return;
    }

    for trace_type in config.trace_types.iter() {
        if trace_type.as_str().len() > u8::MAX as usize {
            continue;
        }

        decode_trace_ids(&payload[para_index..], &trace_type, info);
        if !config.multiple_trace_id_collection && !info.trace_ids.is_empty() {
            break;
        }
    }
    for span_type in config.span_types.iter() {
        if span_type.as_str().len() > u8::MAX as usize {
            continue;
        }

        decode_span_id(&payload[para_index..], &span_type, info);
        if info.span_id.field.len() != 0 {
            break;
        }
    }

    #[cfg(feature = "enterprise")]
    on_payload_and_header(config, direction, port, payload, para_index, info);
}

#[cfg(feature = "enterprise")]
pub fn get_resp_body_info(
    config: &L7LogDynamicConfig,
    payload: &[u8],
    info: &mut DubboInfo,
    direction: PacketDirection,
    port: u16,
) {
    on_payload_and_header(config, direction, port, payload, 0, info);
}

#[cfg(feature = "enterprise")]
fn on_payload_and_header(
    config: &L7LogDynamicConfig,
    direction: PacketDirection,
    port: u16,
    payload: &[u8],
    start: usize,
    info: &mut DubboInfo,
) {
    #[inline]
    fn process_hessian_value(
        fields: &Vec<ExtraField>,
        info: &mut DubboInfo,
        tags: &mut HashMap<&'static str, String>,
        key: &str,
        val: &str,
    ) {
        for field in fields {
            if !field.match_key(&key) {
                continue;
            }

            let Some(value) = field.get_value(&val) else {
                return;
            };
            field.insert_value(value.clone(), tags);
            if let Some(attr_name) = &field.attribute_name {
                info.attributes.push(KeyVal {
                    key: attr_name.to_owned(),
                    val: value.clone(),
                });
            }

            if let Some(metric_name) = &field.metric_name {
                info.metrics.push(MetricKeyVal {
                    key: metric_name.to_owned(),
                    val: value.parse::<f32>().unwrap_or(0.0),
                });
            }
        }
    }

    // 如果配置了需要读取 dubbo header 或 hessian2 payload，则需要解 hessian2 消息
    let Some(policy) = config
        .extra_field_policies
        .get(&L7ProtocolEnum::L7Protocol(L7Protocol::Dubbo))
    else {
        return;
    };
    let Some(indices) = policy.indices.find(port) else {
        return;
    };

    let mut hessian_decoder = Hessian2Decoder::default();
    let mut hessian_payload = None;
    let mut tags = HashMap::new();
    let map_start_index = payload
        .iter()
        .position(|&b| b == BC_MAP || b == BC_MAP_UNTYPED)
        .unwrap_or(0);
    let mut args_end_index: usize = 0;

    for index in indices {
        let Some(policy) = policy.policies.get(*index) else {
            continue;
        };
        let (header_policy, map_string_policy, object_policy) = match direction {
            PacketDirection::ClientToServer => (
                policy.from_req_key.get(&FieldType::DubboHeader),
                policy.from_req_key.get(&FieldType::DubboPayloadMapString),
                policy.from_req_key.get(&FieldType::PayloadHessian2),
            ),
            PacketDirection::ServerToClient => (
                policy.from_resp_key.get(&FieldType::DubboHeader),
                policy.from_resp_key.get(&FieldType::DubboPayloadMapString),
                policy.from_resp_key.get(&FieldType::PayloadHessian2),
            ),
        };

        if let Some(body_object_policy) = object_policy {
            // assume payload is object, which only extract it from start to end, then get value by key
            // 如果 payload 是 object，获取 object field 时，只能精确提取，无法模糊搜索
            if hessian_payload.is_none() {
                (hessian_payload, args_end_index) =
                    hessian_decoder.parse_args(payload, start, direction);
            }

            // 一般而言，args 可能是 string, int, object ...
            // 如果是基本类型，可以直接通过 key 获取到 value，但如果是 object 复合类型，key 只能获取到 object 本身
            // 所以，这里额外支持对象语法，即 x.y 类型的配置，当 value 是 object 时，尝试获取子项，这个场景通常出现在响应出参
            // usually, args maybe (string, int, object ...)
            // if it is a basic type, you can get the value directly by key, but if it is a composite type like object
            // can only get the object itself by key
            // so, we support matching x.y when value is object, this scenario usually occurs in response parameters
            if let Some(hessian_payload_map) = hessian_payload.as_ref() {
                for (key, fields) in body_object_policy {
                    let mut object_map = hessian_payload_map;
                    let mut hessian_val = None;
                    let mut segments = key.split('.').peekable();
                    while let Some(segment) = segments.next() {
                        let Some(val) = object_map.get(segment) else {
                            break;
                        };
                        // peek until meet last key
                        if segments.peek().is_none() {
                            hessian_val = Some(val);
                            break;
                        }
                        let HessianValue::Map(m) = val else {
                            break;
                        };
                        object_map = m;
                    }
                    if let Some(val) = hessian_val {
                        process_hessian_value(
                            fields,
                            info,
                            &mut tags,
                            key.as_str(),
                            &val.to_string(),
                        );
                    };
                }
            };
        }

        if let Some(body_map_string_policy) = map_string_policy {
            // assume payload is a map, try to skip index for search key in payload
            // for map in payload: object{xx, map} can also work, as long as it is map's value
            // 如果 payload 是 map，可以跳索引到 BC_MAP/BC_MAP_UNTYPED 的位置，然后基于 key 来找 value
            // 对 payload 是 object{xx, map} 的情况一样生效，只要是 map 的 value 即可
            for (key, fields) in body_map_string_policy {
                let key_str = key.as_str();
                let Some(val) = hessian_decoder.search_key(payload, key_str, map_start_index)
                else {
                    continue;
                };
                process_hessian_value(fields, info, &mut tags, key_str, &val.to_string());
            }
        }

        if let Some(header_policy) = header_policy {
            // attachment is a hashmap, fuzzy search key to find value, and attachment is after body, so we can skip args_end_index to improve search speed
            // attachment 一定是 map，可以模糊搜索，且 attachment 的起始索引一定在 body 之后，可以用 args_end_index 跳索引来搜索
            for (key, fields) in header_policy {
                let key_str = key.as_str();
                let Some(val) = hessian_decoder.search_key(
                    payload,
                    key_str,
                    args_end_index.max(map_start_index),
                ) else {
                    continue;
                };
                process_hessian_value(fields, info, &mut tags, key_str, &val.to_string());
            }
        }
    }
    info.merge_policy_tags_to_dubbo(&mut tags);
}
