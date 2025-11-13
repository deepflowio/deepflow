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

use std::{collections::HashMap, fmt::Display};

use consts::*;

#[derive(Debug)]
pub enum HessianValue {
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
pub struct Hessian2Decoder {
    class_field_info: Vec<Vec<String>>,
}

impl Hessian2Decoder {
    // 返回具体值和读了多少长度，注意 长度返回 1 表示读取了 start 索引
    pub fn decode_field(&mut self, bytes: &[u8], start: usize) -> (Option<HessianValue>, usize) {
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
    pub fn decode_map(
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
    pub fn decode_list(&mut self, payload: &[u8], index: usize) -> usize {
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
    pub fn decode_obj(
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
    pub fn decode_i32(payload: &[u8], index: usize) -> (i32, usize) {
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
    pub fn decode_i64(payload: &[u8], index: usize) -> (i64, usize) {
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
    pub fn decode_datetime(payload: &[u8], index: usize) -> (i64, usize) {
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
    pub fn decode_f64(payload: &[u8], index: usize) -> (f64, usize) {
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
    pub fn decode_binary(payload: &[u8], index: usize) -> (Vec<u8>, usize) {
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
    pub fn decode_string(payload: &[u8], index: usize) -> (Option<String>, usize) {
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
            if payload[start..start + len].iter().any(|&b| !b.is_ascii()) {
                return (None, 0);
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
        // checked bytes in result are ascii, so unwrap is safe
        (Some(String::from_utf8(result).unwrap()), start - index)
    }
}

pub mod consts {
    pub const BC_END: u8 = b'Z';
    pub const BC_NULL: u8 = b'N'; // x4e
    pub const BC_REF: u8 = 0x51;
    pub const BC_TRUE: u8 = b'T';
    pub const BC_FALSE: u8 = b'F'; // boolean false

    pub const BC_STRING: u8 = b'S'; // final string
    pub const BC_STRING_CHUNK: u8 = b'R'; // non-final string
    pub const BC_STRING_DIRECT: u8 = 0x00;
    pub const STRING_DIRECT_MAX: u8 = 0x1f;
    pub const BC_STRING_SHORT: u8 = 0x30;
    pub const BC_STRING_SHORT_MAX: u8 = 0x33; // STRING_SHORT_MAX >> 8 | BC_STRING_SHORT

    pub const STRING_DIRECT_MAX_LEN: usize = 0x1f;
    pub const STRING_SHORT_MAX_LEN: usize = 0x3ff;
    pub const STRING_MAX_LEN: usize = 0xffff;

    pub const BC_MAP: u8 = 0x4d;
    pub const BC_MAP_UNTYPED: u8 = 0x48;

    pub const BC_OBJECT: u8 = b'O';
    pub const BC_OBJECT_DEF: u8 = b'C';
    pub const BC_OBJECT_DIRECT: u8 = 0x60;
    pub const OBJECT_DIRECT_MAX: u8 = 0x0f;
    // only for BC_OBJECT match
    pub const BC_OBJECT_DIRECT_MAX: u8 = BC_OBJECT_DIRECT + OBJECT_DIRECT_MAX;

    pub const BC_BINARY: u8 = b'B';
    pub const BC_BINARY_CHUNK: u8 = b'A';
    pub const BC_BINARY_DIRECT: u8 = 0x20; // 1-byte length binary
    pub const BINARY_DIRECT_MAX: u8 = 0x0f;
    pub const BC_BINARY_SHORT: u8 = 0x34; // 2-byte length binary
    pub const BINARY_SHORT_MAX: u16 = 0x3ff; // 0-1023 binary

    pub const BC_DATE: u8 = 0x4a; // 64-bit millisecond UTC date
    pub const BC_DATE_MINUTE: u8 = 0x4b; // 32-bit minute UTC date

    pub const BC_DOUBLE: u8 = b'D'; // IEEE 64-bit double
    pub const BC_DOUBLE_ZERO: u8 = 0x5b;
    pub const BC_DOUBLE_ONE: u8 = 0x5c;
    pub const BC_DOUBLE_BYTE: u8 = 0x5d;
    pub const BC_DOUBLE_SHORT: u8 = 0x5e;
    pub const BC_DOUBLE_MILL: u8 = 0x5f;

    pub const BC_INT: u8 = b'I'; // 32-bit int
    pub const BC_INT_ZERO: u8 = 0x90;
    pub const BC_INT_BYTE_ZERO: u8 = 0xc8;
    pub const BC_INT_SHORT_ZERO: u8 = 0xd4;
    pub const INT_DIRECT_MIN: i8 = -0x10;
    pub const INT_DIRECT_MAX: u8 = 0x2f;
    pub const INT_BYTE_MIN: i16 = -0x800;
    pub const INT_BYTE_MAX: u16 = 0x7ff;
    pub const INT_SHORT_MIN: i32 = -0x40000;
    pub const INT_SHORT_MAX: u32 = 0x3ffff;

    pub const BC_LIST_FIXED: u8 = b'V';
    pub const BC_LIST_VARIABLE: u8 = 0x55;
    pub const BC_LIST_VARIABLE_UNTYPED: u8 = 0x57;
    pub const BC_LIST_FIXED_UNTYPED: u8 = 0x58;
    pub const BC_LIST_FIXED_TYPED_LEN_TAG_MIN: u8 = 0x70; // _listFixedTypedLenTagMin
    pub const BC_LIST_FIXED_TYPED_LEN_TAG_MAX: u8 = 0x77; // _listFixedTypedLenTagMax
    pub const BC_LIST_FIXED_UNTYPED_LEN_TAG_MIN: u8 = 0x78; // _listFixedUntypedLenTagMin
    pub const BC_LIST_FIXED_UNTYPED_LEN_TAG_MAX: u8 = 0x7f; // _listFixedUntypedLenTagMax
    pub const BC_LIST_DIRECT: u8 = 0x70;
    pub const BC_LIST_DIRECT_UNTYPED: u8 = 0x78;
    pub const LIST_DIRECT_MAX: u8 = 0x7;

    pub const BC_LONG: u8 = b'L'; // 64-bit signed integer
    pub const BC_LONG_ZERO: u8 = 0xe0;
    pub const LONG_DIRECT_MIN: i8 = -0x08;
    pub const LONG_DIRECT_MAX: u8 = 0x0f;
    pub const BC_LONG_BYTE_ZERO: u8 = 0xf8;
    pub const LONG_BYTE_MIN: i16 = -0x800;
    pub const LONG_BYTE_MAX: u16 = 0x7ff;
    pub const BC_LONG_SHORT_ZERO: u8 = 0x3c;
    pub const LONG_SHORT_MIN: i32 = -0x40000;
    pub const LONG_SHORT_MAX: u32 = 0x3ffff;
    pub const BC_LONG_INT: u8 = 0x59;
}
