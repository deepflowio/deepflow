/*
 * Copyright (c) 2023 Yunshan Networks
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

use public::utils::hash::hash_to_u64;

use super::{forward, ObfuscateCache, BLANK_SPACE, QUESTION_MARK};

const AUTH: &[u8] = "AUTH".as_bytes();
const APPEND: &[u8] = "APPEND".as_bytes();
const GETSET: &[u8] = "GETSET".as_bytes();
const LPUSHX: &[u8] = "LPUSHX".as_bytes();
const GEORADIUSBYMEMBER: &[u8] = "GEORADIUSBYMEMBER".as_bytes();
const RPUSHX: &[u8] = "RPUSHX".as_bytes();
const SETNX: &[u8] = "SETNX".as_bytes();
const SISMEMBER: &[u8] = "SISMEMBER".as_bytes();
const ZRANK: &[u8] = "ZRANK".as_bytes();
const ZREVRANK: &[u8] = "ZREVRANK".as_bytes();
const ZSCORE: &[u8] = "ZSCORE".as_bytes();
const SET: &[u8] = "SET".as_bytes();
const GET: &[u8] = "GET".as_bytes();
const HSET: &[u8] = "HSET".as_bytes();
const HSETNX: &[u8] = "HSETNX".as_bytes();
const LREM: &[u8] = "LREM".as_bytes();
const LSET: &[u8] = "LSET".as_bytes();
const SETBIT: &[u8] = "SETBIT".as_bytes();
const SETEX: &[u8] = "SETEX".as_bytes();
const PSETEX: &[u8] = "PSETEX".as_bytes();
const SETRANGE: &[u8] = "SETRANGE".as_bytes();
const ZINCRBY: &[u8] = "ZINCRBY".as_bytes();
const SMOVE: &[u8] = "SMOVE".as_bytes();
const RESTORE: &[u8] = "RESTORE".as_bytes();
const LINSERT: &[u8] = "LINSERT".as_bytes();
const GEOHASH: &[u8] = "GEOHASH".as_bytes();
const GEOPOS: &[u8] = "GEOPOS".as_bytes();
const GEODIST: &[u8] = "GEODIST".as_bytes();
const LPUSH: &[u8] = "LPUSH".as_bytes();
const RPUSH: &[u8] = "RPUSH".as_bytes();
const SREM: &[u8] = "SREM".as_bytes();
const ZREM: &[u8] = "ZREM".as_bytes();
const SADD: &[u8] = "SADD".as_bytes();
const GEOADD: &[u8] = "GEOADD".as_bytes();
const HMSET: &[u8] = "HMSET".as_bytes();
const MSET: &[u8] = "MSET".as_bytes();
const MSETNX: &[u8] = "MSETNX".as_bytes();
const CONFIG: &[u8] = "CONFIG".as_bytes();
const BITFIELD: &[u8] = "BITFIELD".as_bytes();
const ZADD: &[u8] = "ZADD".as_bytes();
const NX: &[u8] = "NX".as_bytes();
const XX: &[u8] = "XX".as_bytes();
const CH: &[u8] = "CH".as_bytes();
const INCR: &[u8] = "INCR".as_bytes();

const MAX_COMMAND_LENGTH: usize = 17;

pub fn attempt_obfuscation<'a>(
    obfuscate_cache: &Option<ObfuscateCache>,
    input: &[u8],
    remove_all_args: bool,
) -> Option<Vec<u8>> {
    let Some(cache) = obfuscate_cache else {
        return None;
    };
    let key = hash_to_u64(&input);
    if let Some(s) = cache.borrow_mut().get(&key) {
        return Some(s.clone());
    }

    let mut tokenizer = RedisTokenizer::new(input, remove_all_args);
    let mut output = Vec::with_capacity(input.len());
    tokenizer.obfuscate(&mut output);
    let _ = cache.borrow_mut().put(key, output.clone());
    Some(output)
}

struct RedisTokenizer<'a> {
    data: &'a [u8],
    last_is_cmd: bool,
    // merge multiple question marks into one, for example, convert 'GEOPOS key member1 member2' to 'GEOPOS key ?'
    need_masked: bool,
    arg_index: usize,
    // start with the number of arguments after the command mask, for example,
    // 'SET key value', the mask_start_index is 2
    mask_start_index: usize,
    // every number of parameters mask,  for example, 'GEOADD key longitude latitude member longitude
    // latitude member longitude latitude member', every other member needs to be masked, the step is 3
    mask_step: usize,
    last_is_config: bool,
    last_is_bitfield: bool,
    last_is_zadd: bool,
    already_masked: bool,
    remove_all_args: bool,
}

impl RedisTokenizer<'_> {
    fn new(data: &[u8], remove_all_args: bool) -> RedisTokenizer {
        RedisTokenizer {
            data,
            last_is_cmd: false,
            arg_index: 0,
            need_masked: false,
            already_masked: false,
            mask_start_index: 0,
            mask_step: 0,
            last_is_config: false,
            last_is_bitfield: false,
            last_is_zadd: false,
            remove_all_args,
        }
    }

    fn reset(&mut self) {
        self.last_is_cmd = false;
        self.need_masked = false;
        self.arg_index = 0;
        self.mask_start_index = 0;
        self.mask_step = 0;
        self.last_is_config = false;
        self.last_is_bitfield = false;
        self.last_is_zadd = false;
        self.already_masked = false;
    }

    fn obfuscate(&mut self, out: &mut Vec<u8>) {
        let mut start = 0;
        let mut iteration = self.data.iter().enumerate().peekable();
        let mut quoted = false;
        let mut escaped = false;
        let length = self.data.len();

        while let Some(&(i, ch)) = iteration.peek() {
            match ch {
                b' ' => {
                    if !quoted {
                        if self.already_masked && self.need_masked {
                            forward(&mut iteration, 1);
                            continue;
                        }
                        self.mask_sensitive_data(out, &self.data[start..i]);
                        if !self.last_is_cmd {
                            self.last_is_cmd = true;
                        }
                        // skip space
                        while let Some(_) =
                            iteration.next_if(|&(_, c)| *c == b' ' || *c == b'\t' || *c == b'\r')
                        {
                        }
                        start = iteration.peek().map(|(idx, _)| *idx).unwrap_or(length);
                    } else {
                        forward(&mut iteration, 1);
                    }
                    continue;
                }
                b'\n' => {
                    self.mask_sensitive_data(out, &self.data[start..i]);
                    forward(&mut iteration, 1);
                    start = iteration.peek().map(|(idx, _)| *idx).unwrap_or(length);
                    if iteration.len() > 0 {
                        out.push('\n' as u8);
                    }
                    self.reset();
                    continue;
                }
                b'\\' => {
                    if !escaped {
                        escaped = true;
                        forward(&mut iteration, 1);
                        continue;
                    }
                }
                b'"' => {
                    if !escaped {
                        quoted = !quoted;
                    }
                }
                _ => {
                    if self.already_masked && self.need_masked {
                        forward(&mut iteration, 1);
                        continue;
                    }
                }
            }
            forward(&mut iteration, 1);
        }

        self.mask_sensitive_data(out, &self.data[start..]);
    }

    fn mask_sensitive_data(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let mut is_command = true;

        let command = std::str::from_utf8(data);
        if data.len() <= MAX_COMMAND_LENGTH && command.is_ok() {
            match command.unwrap().to_ascii_uppercase().as_bytes() {
                AUTH => {
                    self.mask_start_index = 1;
                    self.need_masked = true;
                }
                APPEND | GETSET | LPUSHX | GEORADIUSBYMEMBER | RPUSHX | SETNX | SISMEMBER
                | ZRANK | ZREVRANK | ZSCORE => {
                    self.mask_start_index = 2;
                }
                SET => {
                    if self.last_is_config {
                        self.mask_start_index = 2;
                    } else if self.last_is_bitfield {
                        self.mask_start_index = 3;
                    } else {
                        self.mask_start_index = 2;
                    }
                }
                HSET | HSETNX | LREM | LSET | SETBIT | SETEX | PSETEX | SETRANGE | ZINCRBY
                | SMOVE | RESTORE => {
                    self.mask_start_index = 3;
                }
                LINSERT => {
                    self.mask_start_index = 4;
                }
                GEOHASH | GEOPOS | GEODIST | LPUSH | RPUSH | SREM | ZREM | SADD => {
                    self.need_masked = true;
                    self.mask_start_index = 2;
                }
                GEOADD => {
                    self.mask_start_index = 4;
                    self.mask_step = 3;
                }
                HMSET => {
                    self.mask_start_index = 3;
                    self.mask_step = 2;
                }
                MSET | MSETNX => {
                    self.mask_start_index = 2;
                    self.mask_step = 2;
                }
                CONFIG => {
                    self.last_is_config = true;
                }
                BITFIELD => {
                    self.last_is_bitfield = true;
                }
                ZADD => {
                    self.last_is_zadd = true;
                    self.mask_start_index = 3;
                    self.mask_step = 2;
                }
                NX | XX | CH | INCR => {
                    if self.last_is_zadd {
                        self.mask_start_index = 2;
                        self.mask_step = 2;
                    }
                }
                GET => {}
                _ => {
                    is_command = false;
                    self.arg_index += 1;
                }
            }
        } else {
            is_command = false;
            self.arg_index += 1;
        }

        if is_command {
            if self.remove_all_args {
                self.mask_start_index = 1;
                self.need_masked = true;
            }
            self.arg_index = 0;
            if self.last_is_cmd {
                out.push(BLANK_SPACE as u8);
            }
            out.extend_from_slice(data);
        } else if self.mask_step > 0
            && self.arg_index >= self.mask_start_index
            && (self.arg_index - self.mask_start_index) % self.mask_step == 0
            || self.arg_index == self.mask_start_index
        {
            self.already_masked = true;
            out.push(BLANK_SPACE as u8);
            out.push(QUESTION_MARK as u8);
        } else {
            if !self.already_masked && self.need_masked || !self.need_masked {
                if self.last_is_cmd {
                    out.push(BLANK_SPACE as u8);
                }
                out.extend_from_slice(data);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, num::NonZeroUsize, rc::Rc};

    use lru::LruCache;

    use super::{super::OBFUSCATE_CACHE_SIZE, *};

    #[test]
    fn test_redis_obfuscate() {
        let obfuscate_cache = Some(Rc::new(RefCell::new(LruCache::new(
            NonZeroUsize::new(OBFUSCATE_CACHE_SIZE).unwrap(),
        ))));

        let test_cases = [
                ("GET key ", Some("GET key")),
                ("AUTH", Some("AUTH")),
                ("AUTH my-secret-password", Some("AUTH ?")),
                ("AUTH james my-secret-password", Some("AUTH ?")),
                ("HELLO 3 AUTH username passwd SETNAME cliname", Some("HELLO 3 AUTH ?")),
                ("APPEND key value", Some("APPEND key ?")),
                ("GETSET key value", Some("GETSET key ?")),
                ("LPUSHX key value", Some("LPUSHX key ?")),
                ("GEORADIUSBYMEMBER key member radius m|km|ft|mi [WITHCOORD] [WITHDIST] [WITHHASH] [COUNT count] [ASC|DESC] [STORE key] [STOREDIST key]", Some("GEORADIUSBYMEMBER key ? radius m|km|ft|mi [WITHCOORD] [WITHDIST] [WITHHASH] [COUNT count] [ASC|DESC] [STORE key] [STOREDIST key]")),
                ("RPUSHX key value", Some("RPUSHX key ?")),
                ("SET key value", Some("SET key ?")),
                ("SET key value [expiration EX seconds|PX milliseconds] [NX|XX]", Some("SET key ? [expiration EX seconds|PX milliseconds] [NX|XX]")),
                ("SETNX key value", Some("SETNX key ?")),
                ("SISMEMBER key member", Some("SISMEMBER key ?")),
                ("ZRANK key member", Some("ZRANK key ?")),
                ("ZREVRANK key member", Some("ZREVRANK key ?")),
                ("ZSCORE key member", Some("ZSCORE key ?")),
                ("BITFIELD key GET type offset SET type offset value INCRBY type", Some("BITFIELD key GET type offset SET type offset ? INCRBY type")),
                ("BITFIELD key SET type offset value INCRBY type", Some("BITFIELD key SET type offset ? INCRBY type")),
                ("BITFIELD key GET type offset INCRBY type", Some("BITFIELD key GET type offset INCRBY type")),
                ("BITFIELD key SET type offset", Some("BITFIELD key SET type offset")),
                ("CONFIG SET parameter value", Some("CONFIG SET parameter ?")),
                ("CONFIG foo bar baz", Some("CONFIG foo bar baz")),
                ("GEOADD key longitude latitude member longitude latitude member longitude latitude member", Some("GEOADD key longitude latitude ? longitude latitude ? longitude latitude ?")),
                ("GEOADD key longitude latitude member longitude latitude member", Some("GEOADD key longitude latitude ? longitude latitude ?")),
                ("GEOADD key longitude latitude member", Some("GEOADD key longitude latitude ?")),
                ("GEOADD key longitude latitude", Some("GEOADD key longitude latitude")),
                ("GEOADD key", Some("GEOADD key")),
                (
                    "GEOHASH key\nGEOPOS key\n   GEODIST key",
                    Some("GEOHASH key\nGEOPOS key\n GEODIST key"),
                ),
                  ("GEOHASH key member\nGEOPOS key member\nGEODIST key member\n", Some("GEOHASH key ?\nGEOPOS key ?\nGEODIST key ?")),
                  ("GEOHASH key member member member\nGEOPOS key member member \n  GEODIST key member member member", Some("GEOHASH key ?\nGEOPOS key ?\n GEODIST key ?")),
                ("GEOPOS key member [member ...]", Some("GEOPOS key ?")),
                ("SREM key member [member ...]", Some("SREM key ?")),
                ("ZREM key member [member ...]", Some("ZREM key ?")),
                ("SADD key member [member ...]", Some("SADD key ?")),
                ("GEODIST key member1 member2 [unit]", Some("GEODIST key ?")),
                ("LPUSH key value [value ...]", Some("LPUSH key ?")),
                ("RPUSH key value [value ...]", Some("RPUSH key ?")),
                (
                    "HSET key field value \nHSETNX key field value\nBLAH",
                    Some("HSET key field ?\nHSETNX key field ?\nBLAH"),
                ),
                ("HSET key field value", Some("HSET key field ?")),
                ("HSETNX key field value", Some("HSETNX key field ?")),
                ("LREM key count value", Some("LREM key count ?")),
                ("LSET key index value", Some("LSET key index ?")),
                ("SETBIT key offset value", Some("SETBIT key offset ?")),
                ("SETRANGE key offset value", Some("SETRANGE key offset ?")),
                ("SETEX key seconds value", Some("SETEX key seconds ?")),
                ("PSETEX key milliseconds value", Some("PSETEX key milliseconds ?")),
                ("ZINCRBY key increment member", Some("ZINCRBY key increment ?")),
                (
                    "SMOVE source destination member",
                    Some("SMOVE source destination ?"),
                ),
                (
                    "RESTORE key ttl serialized-value [REPLACE]",
                    Some("RESTORE key ttl ? [REPLACE]"),
                ),
                (
                    "LINSERT key BEFORE pivot value",
                    Some("LINSERT key BEFORE pivot ?"),
                ),
                ("LINSERT key AFTER pivot value", Some("LINSERT key AFTER pivot ?")),
                (
                    "HMSET key field value field value",
                    Some("HMSET key field ? field ?"),
                ),
                (
                    "HMSET key field value \n HMSET key field value\n",
                    Some("HMSET key field ?\n HMSET key field ?"),
                ),
                ("HMSET key field", Some("HMSET key field")),
                ("MSET key value key value", Some("MSET key ? key ?")),
                ("MSET\nMSET key value", Some("MSET\nMSET key ?")),
                ("MSET key value", Some("MSET key ?")),
                ("MSETNX key value key value", Some("MSETNX key ? key ?")),
                (
                    "ZADD key score member score member",
                    Some("ZADD key score ? score ?"),
                ),
                (
                    "ZADD key NX score member score member",
                    Some("ZADD key NX score ? score ?"),
                ),
                (
                    "ZADD key NX CH score member score member",
                    Some("ZADD key NX CH score ? score ?"),
                ),
                (
                    "ZADD key NX CH INCR score member score member",
                    Some("ZADD key NX CH INCR score ? score ?"),
                ),
                (
                    "ZADD key XX INCR score member score member",
                    Some("ZADD key XX INCR score ? score ?"),
                ),
                ("ZADD key XX INCR score member", Some("ZADD key XX INCR score ?")),
                ("ZADD key XX INCR score", Some("ZADD key XX INCR score")),
                ("CONFIG command\nSET k v", Some("CONFIG command\nSET k ?")),
                ("SET *😊®© ❤️", Some("SET *😊®© ?")),
                ("SET😊 ❤️*😊®© ❤️", Some("SET😊 ❤️*😊®© ❤️")),
                ("ZADD key 😊 member score 😊", Some("ZADD key 😊 ? score ?")),
            ];
        for (ti, tt) in test_cases.iter().enumerate() {
            assert_eq!(
                attempt_obfuscation(&obfuscate_cache, tt.0.as_bytes(), false),
                tt.1.map(|o| o.as_bytes().to_vec()),
                "{}",
                format!("Test case {}", ti)
            );
        }
    }

    #[test]
    fn test_remove_all_redis_args() {
        let obfuscate_cache = Some(Rc::new(RefCell::new(LruCache::new(
            NonZeroUsize::new(OBFUSCATE_CACHE_SIZE).unwrap(),
        ))));

        let test_cases = [
            ("", Some("")),
            ("SET key value", Some("SET ?")),
            ("GET k", Some("GET ?")),
            ("FAKECMD key value hash", Some("FAKECMD key value hash")),
            ("AUTH password", Some("AUTH ?")),
            ("GET", Some("GET")),
            ("CONFIG SET key value", Some("CONFIG SET ?")),
            ("CONFIG GET key", Some("CONFIG GET ?")),
            ("CONFIG key", Some("CONFIG ?")),
            ("BITFIELD key SET key value GET key", Some("BITFIELD ?")),
            ("BITFIELD key INCRBY value", Some("BITFIELD ?")),
            ("BITFIELD secret key", Some("BITFIELD ?")),
            ("set key value", Some("set ?")),
            ("Get key", Some("Get ?")),
            ("config key", Some("config ?")),
            ("CONFIG get key", Some("CONFIG get ?")),
            ("bitfield key SET key value incrby 3", Some("bitfield ?")),
            ("GET key\nSET key value", Some("GET ?\nSET ?")),
        ];

        for (ti, tt) in test_cases.iter().enumerate() {
            assert_eq!(
                attempt_obfuscation(&obfuscate_cache, tt.0.as_bytes(), true),
                tt.1.map(|o| o.as_bytes().to_vec()),
                "{}",
                format!("Test case {}", ti)
            );
        }
    }
}
