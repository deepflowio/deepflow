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

/// 单次流式解析会话。位置状态由自身维护，所有 decode 方法直接操作 self.pos。
/// class_field_info 是 per-stream 状态（BC_OBJECT_DEF 先于 BC_OBJECT 出现），也属于会话。
pub struct Hessian2IterDecoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    class_field_info: Vec<Vec<String>>,
}

impl<'a> Hessian2IterDecoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0, class_field_info: Vec::new() }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn consume(&mut self) -> Option<u8> {
        let b = self.bytes.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_to_end(&mut self) {
        self.pos = self.bytes.len();
    }

    // 严格解析当前位置的一个字段，消费对应字节并返回结果。
    // BC_REF、list 等无实用值的字段返回 None（pos 仍推进）。
    // 供 decode_map / decode_obj / decode_list 内部使用；外部请用 decode_field。
    fn decode_one(&mut self) -> Option<HessianValue> {
        let tag = match self.peek() {
            None | Some(BC_END) => return None,
            Some(t) => t,
        };
        let prev = self.pos;
        let result = match tag {
            BC_NULL => { self.pos += 1; Some(HessianValue::Null) }
            BC_TRUE => { self.pos += 1; Some(HessianValue::Bool(true)) }
            BC_FALSE => { self.pos += 1; Some(HessianValue::Bool(false)) }
            BC_REF => {
                self.pos += 1; // 跳过 BC_REF tag 本身
                self.decode_i32(); // 跳过 ref 索引
                None
            }
            // int
            0x80..=0xbf | 0xc0..=0xcf | 0xd0..=0xd7 | BC_INT => {
                Some(HessianValue::Int(self.decode_i32()))
            }
            // long
            0xd8..=0xef | 0xf0..=0xff | 0x38..=0x3f | BC_LONG_INT | BC_LONG => {
                Some(HessianValue::Long(self.decode_i64()))
            }
            // date
            BC_DATE | BC_DATE_MINUTE => Some(HessianValue::DateTime(self.decode_datetime())),
            // double
            BC_DOUBLE_ZERO | BC_DOUBLE_ONE | BC_DOUBLE_BYTE | BC_DOUBLE_SHORT | BC_DOUBLE_MILL
            | BC_DOUBLE => Some(HessianValue::Double(self.decode_f64())),
            // binary
            BC_BINARY_DIRECT..=INT_DIRECT_MAX
            | BC_BINARY_SHORT..=0x37
            | BC_BINARY_CHUNK
            | BC_BINARY => Some(HessianValue::Binary(self.decode_binary())),
            // string
            BC_STRING_SHORT..=BC_STRING_SHORT_MAX
            | BC_STRING_DIRECT..=STRING_DIRECT_MAX
            | BC_STRING_CHUNK
            | BC_STRING => {
                if let Some(s) = self.decode_string() {
                    Some(HessianValue::String(s))
                } else {
                    // tag 表示为 string 但无法读出合法的 string，数据异常，丢弃剩余
                    self.skip_to_end();
                    None
                }
            }
            // list: 没有实用意义，跳过即可
            BC_LIST_DIRECT..=0x77
            | BC_LIST_DIRECT_UNTYPED..=0x7f
            | BC_LIST_FIXED
            | BC_LIST_VARIABLE
            | BC_LIST_FIXED_UNTYPED
            | BC_LIST_VARIABLE_UNTYPED => {
                self.decode_list();
                None
            }
            // hashmap
            BC_MAP | BC_MAP_UNTYPED => Some(HessianValue::Map(self.decode_map())),
            // object
            BC_OBJECT_DEF | BC_OBJECT | BC_OBJECT_DIRECT..=BC_OBJECT_DIRECT_MAX => {
                Some(HessianValue::Map(self.decode_obj()))
            }
            _ => { self.skip_to_end(); None }
        };
        // 子解码器遇到字节不足时可能不推进 pos，强制跳过剩余，防止调用方死循环
        if self.pos == prev {
            self.skip_to_end();
        }
        result
    }

    // 返回下一个有意义的字段，跳过 BC_REF、list 等无值标记。
    // 供 Iterator::next 及外部直接使用。
    pub fn decode_field(&mut self) -> Option<HessianValue> {
        loop {
            match self.peek() {
                None | Some(BC_END) => return None,
                _ => {}
            }
            let prev = self.pos;
            let value = self.decode_one();
            if self.pos == prev {
                return None; // 安全兜底：无进展则终止
            }
            if value.is_some() {
                return value;
            }
            // BC_REF、list：pos 已推进但无值，继续找下一个
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/map.go#L240
    pub fn decode_map(&mut self) -> HashMap<String, HessianValue> {
        let mut map = HashMap::new();
        let tag = match self.consume() {
            None => return map,
            Some(t) => t,
        };
        if self.pos >= self.bytes.len() {
            return map;
        }
        if tag == BC_MAP {
            // typed map：跳过类型字符串，忽略实际类型。
            // 若类型头不是合法字符串则直接放弃跳过——不做 i32 fallback，
            // 避免误消费后续的 key 字节。
            self.decode_string();
        }
        loop {
            match self.peek() {
                None => break,
                Some(BC_END) => { self.pos += 1; break; }
                _ => {}
            }
            let before_key = self.pos;
            let key = self.decode_one();
            if self.pos == before_key {
                break; // key 解析无进展，防止死循环
            }
            let before_val = self.pos;
            let value = self.decode_one();
            if self.pos == before_val {
                break; // value 解析无进展，防止死循环
            }
            if let (Some(HessianValue::String(k)), Some(v)) = (key, value) {
                map.insert(k, v);
            }
        }
        map
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/list.go#L280
    // list 具体值无用，只需跳过正确长度
    pub fn decode_list(&mut self) {
        let tag = match self.consume() {
            None => return,
            Some(t) => t,
        };
        if self.pos >= self.bytes.len() {
            return;
        }
        let arr_len = match tag {
            BC_LIST_FIXED => {
                self.decode_string(); // 跳过类型字符串
                if self.pos >= self.bytes.len() {
                    return;
                }
                self.decode_i32().max(0) as usize
            }
            BC_LIST_VARIABLE => {
                self.decode_string(); // 跳过类型字符串
                if self.pos >= self.bytes.len() {
                    return;
                }
                // 未知长度，读到第一个 BC_END
                self.pos += self.bytes[self.pos..]
                    .iter()
                    .position(|&b| b == BC_END)
                    .map(|p| p + 1)
                    .unwrap_or(self.bytes.len() - self.pos);
                return;
            }
            BC_LIST_FIXED_TYPED_LEN_TAG_MIN..=BC_LIST_FIXED_TYPED_LEN_TAG_MAX => {
                self.decode_string(); // 跳过类型字符串
                tag.overflowing_sub(BC_LIST_FIXED_TYPED_LEN_TAG_MIN).0 as usize
            }
            BC_LIST_FIXED_UNTYPED => self.decode_i32().max(0) as usize,
            BC_LIST_VARIABLE_UNTYPED => {
                self.pos += self.bytes[self.pos..]
                    .iter()
                    .position(|&b| b == BC_END)
                    .map(|p| p + 1)
                    .unwrap_or(self.bytes.len() - self.pos);
                return;
            }
            BC_LIST_FIXED_UNTYPED_LEN_TAG_MIN..=BC_LIST_FIXED_UNTYPED_LEN_TAG_MAX => {
                tag.overflowing_sub(BC_LIST_FIXED_UNTYPED_LEN_TAG_MIN).0 as usize
            }
            _ => return,
        };
        for _ in 0..arr_len {
            if self.pos >= self.bytes.len() {
                break;
            }
            self.decode_one();
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/object.go#L567
    pub fn decode_obj(&mut self) -> HashMap<String, HessianValue> {
        let mut object_map = HashMap::new();
        let tag = match self.consume() {
            None => return object_map,
            Some(t) => t,
        };
        match tag {
            BC_OBJECT_DEF => {
                self.decode_string(); // 跳过类名
                if self.pos >= self.bytes.len() {
                    return object_map;
                }
                let field_num = self.decode_i32().max(0) as usize;
                let mut field_list = Vec::with_capacity(field_num);
                for _ in 0..field_num {
                    if self.pos >= self.bytes.len() {
                        break;
                    }
                    if let Some(field_name) = self.decode_string() {
                        field_list.push(field_name);
                    } else {
                        break;
                    }
                }
                // 先把 BC_OBJECT_DEF 的字段定义加入索引
                self.class_field_info.push(field_list);
                // 跳到 BC_OBJECT 继续解析实例数据
                match self.decode_one() {
                    Some(HessianValue::Map(map)) => map,
                    _ => object_map,
                }
            }
            BC_OBJECT | BC_OBJECT_DIRECT..=BC_OBJECT_DIRECT_MAX => {
                let class_index = if tag == BC_OBJECT {
                    self.decode_i32() as usize
                } else {
                    tag.overflowing_sub(BC_OBJECT_DIRECT).0 as usize
                };
                if class_index >= self.class_field_info.len() {
                    return object_map;
                }
                let field_list = self.class_field_info[class_index].clone();
                for field_name in &field_list {
                    if self.pos >= self.bytes.len() {
                        break;
                    }
                    if let Some(value) = self.decode_one() {
                        object_map.insert(field_name.clone(), value);
                    }
                }
                object_map
            }
            _ => object_map,
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/int.go#L60
    pub fn decode_i32(&mut self) -> i32 {
        let index = self.pos;
        if index >= self.bytes.len() {
            return 0;
        }
        let tag = self.bytes[index];
        match tag {
            0x80..=0xbf => { self.pos += 1; tag.overflowing_sub(BC_INT_ZERO).0 as i32 }
            0xc0..=0xcf if index + 1 < self.bytes.len() => {
                self.pos += 2;
                u16::from_be_bytes([tag.overflowing_sub(BC_INT_BYTE_ZERO).0, self.bytes[index + 1]]) as i32
            }
            0xd0..=0xd7 if index + 2 < self.bytes.len() => {
                self.pos += 3;
                let mut buf = [0, tag.overflowing_sub(BC_INT_SHORT_ZERO).0, self.bytes[index + 1], self.bytes[index + 2]];
                if buf[1] & 0x80 != 0 { buf[0] = 0xff; }
                u32::from_be_bytes(buf) as i32
            }
            BC_INT if index + 4 < self.bytes.len() => {
                self.pos += 5;
                i32::from_be_bytes(self.bytes[index + 1..index + 5].try_into().unwrap_or_default())
            }
            _ => 0
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/long.go#L63
    pub fn decode_i64(&mut self) -> i64 {
        let index = self.pos;
        if index >= self.bytes.len() {
            return 0;
        }
        let tag = self.bytes[index];
        match tag {
            0xd8..=0xef => { self.pos += 1; tag.overflowing_sub(BC_LONG_ZERO).0 as i64 }
            0xf0..=0xff if index + 1 < self.bytes.len() => {
                self.pos += 2;
                u16::from_be_bytes([tag.overflowing_sub(BC_LONG_BYTE_ZERO).0, self.bytes[index + 1]]) as i64
            }
            0x38..=0x3f if index + 2 < self.bytes.len() => {
                self.pos += 3;
                let mut buf = [0, tag.overflowing_sub(BC_LONG_SHORT_ZERO).0, self.bytes[index + 1], self.bytes[index + 2]];
                if buf[1] & 0x80 != 0 { buf[0] = 0xff; }
                u32::from_be_bytes(buf) as i64
            }
            BC_LONG_INT if index + 4 < self.bytes.len() => {
                self.pos += 5;
                i32::from_be_bytes(self.bytes[index + 1..index + 5].try_into().unwrap_or_default()) as i64
            }
            BC_LONG if index + 8 < self.bytes.len() => {
                self.pos += 9;
                i64::from_be_bytes(self.bytes[index + 1..index + 9].try_into().unwrap_or_default())
            }
            _ => 0
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/date.go#L60
    pub fn decode_datetime(&mut self) -> i64 {
        let index = self.pos;
        if index >= self.bytes.len() {
            return 0;
        }
        let tag = self.bytes[index];
        match tag {
            BC_DATE if index + 8 < self.bytes.len() => {
                self.pos += 9;
                u64::from_be_bytes(self.bytes[index + 1..index + 9].try_into().unwrap_or_default()) as i64
            }
            BC_DATE_MINUTE if index + 4 < self.bytes.len() => {
                self.pos += 5;
                // fix: 先 cast 再乘，避免 u32 乘法溢出后才 cast 到 i64
                u32::from_be_bytes(self.bytes[index + 1..index + 5].try_into().unwrap_or_default()) as i64 * 60
            }
            _ => 0
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/double.go#L109
    pub fn decode_f64(&mut self) -> f64 {
        let index = self.pos;
        if index >= self.bytes.len() {
            return 0.0;
        }
        let tag = self.bytes[index];
        match tag {
            BC_DOUBLE_ZERO => { self.pos += 1; 0.0 }
            BC_DOUBLE_ONE => { self.pos += 1; 1.0 }
            BC_DOUBLE_BYTE if index + 1 < self.bytes.len() => {
                self.pos += 2;
                u8::from_be_bytes(self.bytes[index + 1..index + 2].try_into().unwrap_or_default()) as f64
            }
            BC_DOUBLE_SHORT if index + 2 < self.bytes.len() => {
                self.pos += 3;
                u16::from_be_bytes(self.bytes[index + 1..index + 3].try_into().unwrap_or_default()) as f64
            }
            BC_DOUBLE_MILL if index + 4 < self.bytes.len() => {
                self.pos += 5;
                u32::from_be_bytes(self.bytes[index + 1..index + 5].try_into().unwrap_or_default()) as f64
            }
            BC_DOUBLE if index + 8 < self.bytes.len() => {
                self.pos += 9;
                f64::from_be_bytes(self.bytes[index + 1..index + 9].try_into().unwrap_or_default())
            }
            _ => 0.0
        }
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/binary.go#L124
    pub fn decode_binary(&mut self) -> Vec<u8> {
        let mut result = Vec::new();
        loop {
            let index = self.pos;
            if index >= self.bytes.len() {
                break;
            }
            let tag = self.bytes[index];
            let len = match tag {
                BC_BINARY_DIRECT..=INT_DIRECT_MAX => {
                    self.pos += 1;
                    tag.overflowing_sub(BC_BINARY_DIRECT).0 as usize
                }
                BC_BINARY_SHORT..=0x37 if index + 1 < self.bytes.len() => {
                    self.pos += 2;
                    // fix: 原代码 `<< 8 + bytes[...]` 因 Rust 优先级被解析为 `<< (8 + bytes[...])`
                    (((tag.overflowing_sub(BC_BINARY_SHORT).0) as usize) << 8) + self.bytes[index + 1] as usize
                }
                BC_BINARY_CHUNK | BC_BINARY if index + 2 < self.bytes.len() => {
                    self.pos += 3;
                    ((self.bytes[index + 1] as usize) << 8) + self.bytes[index + 2] as usize
                }
                _ => break,
            };
            if self.pos + len > self.bytes.len() {
                self.skip_to_end();
                break;
            }
            result.extend_from_slice(&self.bytes[self.pos..self.pos + len]);
            self.pos += len;
            if tag != BC_BINARY_CHUNK {
                break;
            }
        }
        result
    }

    // https://github.com/apache/dubbo-go-hessian2/blob/master/string.go#L204
    pub fn decode_string(&mut self) -> Option<String> {
        let mut result = Vec::new();
        loop {
            let index = self.pos;
            if index >= self.bytes.len() {
                break;
            }
            let tag = self.bytes[index];
            let (data_start, len) = match tag {
                BC_STRING_DIRECT..=STRING_DIRECT_MAX => (index + 1, tag as usize),
                BC_STRING_SHORT..=BC_STRING_SHORT_MAX if index + 1 < self.bytes.len() => {
                    let len = (((self.bytes[index] - BC_STRING_SHORT) as usize) << 8)
                        + self.bytes[index + 1] as usize;
                    (index + 2, len)
                }
                BC_STRING_CHUNK | BC_STRING if index + 2 < self.bytes.len() => {
                    let len = ((self.bytes[index + 1] as usize) << 8) + self.bytes[index + 2] as usize;
                    (index + 3, len)
                }
                _ => return None,
            };
            if data_start + len > self.bytes.len() {
                self.skip_to_end();
                break;
            }
            if self.bytes[data_start..data_start + len].iter().any(|&b| !b.is_ascii()) {
                // 非 ASCII 不推进 pos，由调用方决定如何处理
                return None;
            }
            result.extend_from_slice(&self.bytes[data_start..data_start + len]);
            self.pos = data_start + len;
            if tag != BC_STRING_CHUNK {
                break;
            }
        }
        // checked bytes in result are ascii, so unwrap is safe
        Some(String::from_utf8(result).unwrap())
    }
}

impl<'a> Iterator for Hessian2IterDecoder<'a> {
    type Item = HessianValue;

    fn next(&mut self) -> Option<Self::Item> {
        self.decode_field()
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
