/*
 * Copyright (c) 2024 Yunshan Networks
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

use std::ops::RangeInclusive;

use public::bytes::{read_u16_be, read_u32_be, read_u64_be};

const LONG_8_BYTES: u8 = 0x4c;
const LONG_1_BYTES: RangeInclusive<u8> = 0xd8..=0xef;
const LONG_2_BYTES: RangeInclusive<u8> = 0xf0..=0xff;
const LONG_3_BYTES: RangeInclusive<u8> = 0x38..=0x3f;
const INTEGER_4_BYTES: u8 = 0x49;
const INTEGER_1_BYTES: RangeInclusive<u8> = 0x80..=0xbf;
const INTEGER_2_BYTES: RangeInclusive<u8> = 0xc0..=0xcf;
const INTEGER_3_BYTES: RangeInclusive<u8> = 0xd0..=0xd7;

const STRING_LEN_0_31: RangeInclusive<u8> = 0x00..=0x1f;
const STRING_LEN_0_1023: RangeInclusive<u8> = 0x30..=0x33;
const STRING_LEN_2_BYTES: u8 = 0x53;

const NULL: u8 = 0x4e;

const TREE_MAP: u8 = 0x4d;
const MAP_END: u8 = 0x5a;

const OBJ: u8 = 0x4f;
const OBJ_INSTANCE: RangeInclusive<u8> = 0x60..=0x6f;

#[derive(Debug, PartialEq)]
pub enum FieldEnum<'a> {
    Integer(i64),
    String(&'a str),
    NULL,
}

pub struct HessianObjIterator<'a> {
    off: usize,
    payload: &'a [u8],
    field_list: Vec<&'a str>,
    current_field_idx: usize,
    in_map_count: usize,
}

impl<'a> HessianObjIterator<'a> {
    // reference http://hessian.caucho.com/doc/hessian-serialization.html#anchor11
    // obj hessian2 encode: | b'O' | class name len | field desc | b'o' | ref | class instance value |
    pub fn new(payload: &'a [u8]) -> Option<Self> {
        let mut s = Self {
            payload,
            off: 0,
            field_list: vec![],
            current_field_idx: 0,
            in_map_count: 0,
        };

        let Some(b) = s.read_n_bytes(1) else {
            return None;
        };
        if b[0] != OBJ {
            return None;
        }

        let Some(class_name_len) = s.read_integer(None) else {
            return None;
        };

        s.off += class_name_len as usize;

        let Some(field_len) = s.read_integer(None) else {
            return None;
        };

        for _ in 0..field_len {
            let Some(field) = s.read_string(None) else {
                return None;
            };
            s.field_list.push(field);
        }

        let Some(b) = s.read_n_bytes(1) else {
            return None;
        };
        if !OBJ_INSTANCE.contains(&b[0]) {
            return None;
        }
        // read ref
        s.read_n_bytes(1);

        // the rest is the field value
        Some(s)
    }

    fn read_field(&mut self) -> Option<(&'a str, FieldEnum<'a>)> {
        let Some(b0) = self.read_n_bytes(1).map(|b| b[0]) else {
            return None;
        };
        match b0 {
            TREE_MAP => {
                self.in_map_count += 1;
                return self.read_field();
            }
            MAP_END => {
                self.in_map_count -= 1;
                return self.read_field();
            }
            _ => {}
        }

        if self.in_map_count != 0 {
            return self.read_map(Some(b0));
        }
        self.read_basic_field(Some(b0))
    }

    // current only support string, int
    fn read_basic_field(&mut self, first_byte: Option<u8>) -> Option<(&'a str, FieldEnum<'a>)> {
        let Some(b0) = first_byte.or_else(|| self.read_n_bytes(1).map(|b| b[0])) else {
            return None;
        };

        if self.current_field_idx >= self.field_list.len() {
            return None;
        }

        let field_name = *(self.field_list.get(self.current_field_idx).unwrap());

        if self.in_map_count == 0 {
            self.current_field_idx += 1;
        }

        if b0 == LONG_8_BYTES
            || b0 == INTEGER_4_BYTES
            || LONG_1_BYTES.contains(&b0)
            || LONG_2_BYTES.contains(&b0)
            || LONG_3_BYTES.contains(&b0)
            || INTEGER_1_BYTES.contains(&b0)
            || INTEGER_2_BYTES.contains(&b0)
            || INTEGER_3_BYTES.contains(&b0)
        {
            self.read_integer(Some(b0)).map(|i| FieldEnum::Integer(i))
        } else if b0 == STRING_LEN_2_BYTES
            || STRING_LEN_0_1023.contains(&b0)
            || STRING_LEN_0_31.contains(&b0)
        {
            self.read_string(Some(b0)).map(|s| FieldEnum::String(s))
        } else if b0 == NULL {
            Some(FieldEnum::NULL)
        } else {
            None
        }
        .map(|f| (field_name, f))
    }

    fn read_integer(&mut self, first_byte: Option<u8>) -> Option<i64> {
        let Some(b0) = first_byte.or_else(|| self.read_n_bytes(1).map(|b| b[0])) else {
            return None;
        };

        match b0 {
            // int
            INTEGER_4_BYTES => self
                .read_n_bytes(4)
                .and_then(|b| Some(read_u32_be(b) as i64)),
            _ if INTEGER_1_BYTES.contains(&b0) => Some(b0 as i64 - 0x90),
            _ if INTEGER_2_BYTES.contains(&b0) => self
                .read_n_bytes(1)
                .and_then(|b1| Some(((b0 as i64) << 8) + b1[0] as i64 - 0xc800)),
            _ if INTEGER_3_BYTES.contains(&b0) => self.read_n_bytes(2).and_then(|b| {
                let (b1, b2) = (b[0] as i64, b[1] as i64);
                Some(((b0 as i64) << 16) + b1 + b2 - 0xd40000)
            }),

            LONG_8_BYTES => self
                .read_n_bytes(8)
                .and_then(|b| Some(read_u64_be(b) as i64)),
            _ if LONG_1_BYTES.contains(&b0) => Some(b0 as i64 - 0xe0),
            _ if LONG_2_BYTES.contains(&b0) => self
                .read_n_bytes(1)
                .and_then(|b| Some(((b0 as i64) << 8) + b[0] as i64 - 0xf800)),
            _ if LONG_3_BYTES.contains(&b0) => self.read_n_bytes(2).and_then(|b| {
                let (b1, b2) = (b[0] as i64, b[1] as i64);
                Some(((b0 as i64) << 16) + (b1 << 8) + b2 - 0x3c0000)
            }),
            _ => None,
        }
    }

    fn read_string(&mut self, first_byte: Option<u8>) -> Option<&'a str> {
        let Some(b0) = first_byte.or_else(|| self.read_n_bytes(1).map(|b| b[0])) else {
            return None;
        };
        match b0 {
            _ if STRING_LEN_0_31.contains(&b0) => self
                .read_n_bytes(b0 as usize)
                .and_then(|s| std::str::from_utf8(s).map_or(None, |s| Some(s))),
            _ if STRING_LEN_0_1023.contains(&b0) => {
                let Some(b1) = self.read_n_bytes(1) else {
                    return None;
                };
                let b1 = b1[0];
                self.read_n_bytes((b0 - 0x30) as usize + b1 as usize)
                    .and_then(|s| std::str::from_utf8(s).map_or(None, |s| Some(s)))
            }
            STRING_LEN_2_BYTES => {
                let Some(l) = self.read_n_bytes(2) else {
                    return None;
                };
                let l = read_u16_be(l) as usize;
                self.read_n_bytes(l)
                    .and_then(|s| std::str::from_utf8(s).map_or(None, |s| Some(s)))
            }
            // not support x52 chunk string
            _ => None,
        }
    }

    fn read_map(&mut self, first_byte: Option<u8>) -> Option<(&'a str, FieldEnum<'a>)> {
        let Some((_, key)) = self.read_basic_field(first_byte) else {
            return None;
        };

        if let FieldEnum::String(k1) = key {
            let Some(b0) = self.read_n_bytes(1).map(|b| b[0]) else {
                return None;
            };

            match b0 {
                TREE_MAP => {
                    self.in_map_count += 1;
                    return self.read_field();
                }
                MAP_END => {
                    self.in_map_count -= 1;
                    return self.read_field();
                }
                _ => {}
            }

            let Some((_, val)) = self.read_basic_field(Some(b0)) else {
                return None;
            };
            Some((k1, val))
        } else {
            None
        }
    }

    fn read_n_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.off + n > self.payload.len() {
            return None;
        }
        self.off += n;
        Some(&self.payload[self.off - n..self.off])
    }
}

impl<'a> Iterator for HessianObjIterator<'a> {
    type Item = (&'a str, FieldEnum<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        self.read_field()
    }
}

#[cfg(test)]
mod test {
    use super::{FieldEnum, HessianObjIterator};

    #[test]
    fn test_hessian1() {
        let b = "4fbc636f6d2e616c697061792e736f66612e7270632e636f72652e726571756573742e536f666152657175657374950d7461726765744170704e616d650a6d6574686f644e616d651774617267657453657276696365556e697175654e616d650c7265717565737450726f70730d6d6574686f64417267536967736f904e0b746573745375636365737353002a636f6d2e6d79636f6d70616e792e6170702e636f6d6d6f6e2e53657276496e746572666163653a312e304d0870726f746f636f6c04626f6c74156e65775f7270635f74726163655f636f6e7465787453003e746369643d30613232303063653136373039303032383339353631303038313335323526737069643d302670737069643d2673616d706c653d74727565267a567400075b737472696e676e011c636f6d2e6d79636f6d70616e792e6170702e636f6d6d6f6e2e5265717a4fac636f6d2e6d79636f6d70616e792e6170702e636f6d6d6f6e2e52657192046e616d65036167656f911e616161616161616161616161616161616161616161616161616161616161cbe7";
        let d = hex::decode(b).unwrap();
        for (k, v) in HessianObjIterator::new(d.as_slice()).unwrap() {
            match k {
                "targetAppName" => assert_eq!(v, FieldEnum::NULL),
                "methodName" => assert_eq!(v, FieldEnum::String("testSuccess")),
                "targetServiceUniqueName" => assert_eq!(
                    v,
                    FieldEnum::String("com.mycompany.app.common.ServInterface:1.0")
                ),
                "protocol" => assert_eq!(v, FieldEnum::String("bolt")),
                "new_rpc_trace_context" => assert_eq!(
                    v,
                    FieldEnum::String(
                        "tcid=0a2200ce1670900283956100813525&spid=0&pspid=&sample=true&"
                    )
                ),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_hessian2() {
        let b = "4fbc636f6d2e616c697061792e736f66612e7270632e636f72652e726571756573742e536f666152657175657374950d7461726765744170704e616d650a6d6574686f644e616d651774617267657453657276696365556e697175654e616d650c7265717565737450726f70730d6d6574686f64417267536967736f90076473675f64736706696e766f6b6553002c636f6d2e697466696e2e6473672e6473672e6661636164652e45534250726f7879536572766963653a312e304d036170700b6463635f616461707465720870726f746f636f6c04626f6c74117270635f74726163655f636f6e746578744d09736f6661527063496407302e312e322e310b73797350656e4174747273000d736f666143616c6c6572496463000c736f666143616c6c65724970000b736f6661547261636549641e3061306239613439313638333235353336323732373338393531353832370c736f666150656e417474727353013e696e737449643d39393939303130322674656e616e7449643d393939392646435f4556454e545f434f4e544558543d7b22616363657373546f6b656e223a22656265222c22617574684964223a2241303031222c2262697a50726f64436f6465223a2250524f44303031222c226368616e6e656c44617465223a313638333235353336323732382c226368616e6e656c4576656e74436f6465223a2245565430303031222c226368616e6e656c4964223a2233323030303537222c226368616e6e656c50726f64436f6465223a2250524f44303031222c226368616e6e656c5365714e6f223a2241473230323330353035383638383038303538303630363036222c22696e73744964223a223939393930313032222c226f70657261746f72223a2231303030303535222c2274656e616e744964223a2239393939227d260e736f666143616c6c65725a6f6e65000d736f666143616c6c6572417070007a7a567400075b737472696e676e01106a6176612e6c616e672e4f626a6563747a4fb4636f6d2e64632e676f7665726e616e63652e6d657461646174612e696d706c732e53444f92046e616d65076f626a656374736f91004d1c2f73646f726f6f742f6c6f63616c5f686561642f73686f71667368694e192f73646f726f6f742f7379735f686561642f76657273696f6e05312e302e301c2f73646f726f6f742f6c6f63616c5f686561642f697064697a6869694e1c2f73646f726f6f742f6c6f63616c5f686561642f776169626c697573154742323032333035303531303536303232363437311c2f73646f726f6f742f6c6f63616c5f686561642f677569797a7762734e1c2f73646f726f6f742f6c6f63616c5f686561642f7a686169796f646d4e1c2f73646f726f6f742f6c6f63616c5f686561642f6635357978696e784e1a2f73646f726f6f742f7379735f686561642f7265737064617465001c2f73646f726f6f742f6c6f63616c5f686561642f73686f71677569794e1c2f73646f726f6f742f6c6f63616c5f686561642f73686f7171727a774e1c2f73646f726f6f742f6c6f63616c5f686561642f73667a6865636a674e1a2f73646f726f6f742f7379735f686561642f7072696f726974790230301c2f73646f726f6f742f6c6f63616c5f686561642f79637371627a68694e1c2f73646f726f6f742f6c6f63616c5f686561642f68656a696a696e654e1c2f73646f726f6f742f6c6f63616c5f686561642f73686f716a676a624e1c2f73646f726f6f742f6c6f63616c5f686561642f677569797a77656e4e1c2f73646f726f6f742f6c6f63616c5f686561642f6a69616f796967";
        let d = hex::decode(b).unwrap();
        for (k, v) in HessianObjIterator::new(d.as_slice()).unwrap() {
            match k {
                "targetAppName" => assert_eq!(v, FieldEnum::String("dsg_dsg")),
                "methodName" => assert_eq!(v, FieldEnum::String("invoke")),
                "targetServiceUniqueName" => assert_eq!(
                    v,
                    FieldEnum::String("com.itfin.dsg.dsg.facade.ESBProxyService:1.0")
                ),
                "app" => assert_eq!(v, FieldEnum::String("dcc_adapter")),
                "protocol" => assert_eq!(v, FieldEnum::String("bolt")),
                "sofaRpcId" => assert_eq!(v, FieldEnum::String("0.1.2.1")),
                "sysPenAttrs" => assert_eq!(v, FieldEnum::String("")),
                "sofaCallerIdc" => assert_eq!(v, FieldEnum::String("")),
                "sofaCallerIp" => assert_eq!(v, FieldEnum::String("")),
                "sofaTraceId" => assert_eq!(v, FieldEnum::String("0a0b9a491683255362727389515827")),
                "sofaPenAttrs" => {}
                "sofaCallerZone" => assert_eq!(v, FieldEnum::String("")),
                "sofaCallerApp" => assert_eq!(v, FieldEnum::String("")),
                _ => unreachable!(),
            }
        }
    }
}
