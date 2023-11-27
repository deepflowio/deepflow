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

use public::ringbuffer::RingBufSlice;

use crate::tcp_reassemble::TcpFragementMeta;

pub enum Payload<'a> {
    // 不支持重组,数据来自 metapacket
    // 或buffer是空的情况,先尝试解析,需要更多数据再放进 buffer
    // (payload, can reassemble, tcp seq)
    MetaPacket(TcpPayload<'a>),
    // from tcp reassemble get consequent buffer, need to drop the frame in buffer when parse success or fail
    // nothing to do when return NeedMoreData error,
    InFlightBuffer(RingBufSlice<'a, u8>, &'a mut [TcpFragementMeta]),
    // from tcp reassemble flush buffer, buffer not need to mut regardless parse fail or success
    FlushedBuffer(Vec<(Vec<u8>, Vec<TcpFragementMeta>)>),
}

pub struct PayloadReader<'a> {
    payload: Payload<'a>,
    // 当前读取帧相对 frame start 的结束偏移
    tcp_frame_off: usize,
    // 起始读取帧指针
    tcp_frame_start: usize,
    // 当前 payload 起始指针,对应 所有tcp_frame_skip 的帧长度
    payload_start: usize,
    // 当前读取帧对应在 payload start 的结束偏移
    payload_off: usize,
    buffer_idx: usize,
}

impl<'a> PayloadReader<'a> {
    pub fn new(mut v: Payload<'a>) -> Self {
        let (tcp_frame_off, payload_off, buffer_idx) = match &mut v {
            Payload::MetaPacket(_) => (0usize, 0usize, 0usize),
            Payload::InFlightBuffer(_, ref frames) => {
                let (mut tcp_frame_idx, mut payload_off) = (0, 0);
                for t in frames.iter() {
                    if !t.is_parsed {
                        break;
                    }
                    payload_off += t.payload_len;
                    tcp_frame_idx += 1;
                }
                (tcp_frame_idx, payload_off, 0)
            }
            Payload::FlushedBuffer(ref buffer) => {
                let (_, frames) = buffer.first().unwrap();
                let (mut tcp_frame_idx, mut payload_off) = (0, 0);
                for t in frames.iter() {
                    if !t.is_parsed {
                        break;
                    }
                    payload_off += t.payload_len;
                    tcp_frame_idx += 1;
                }
                if tcp_frame_idx == frames.len() {
                    (0, 0, 1)
                } else {
                    (tcp_frame_idx, payload_off, 0)
                }
            }
        };
        Self {
            payload: v,
            tcp_frame_start: 0,
            tcp_frame_off,
            payload_start: 0,
            payload_off,
            buffer_idx,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpPayload<'a> {
    pub payload: &'a [u8],
    pub seq: u32,
    pub cap_seq:u64,
    pub can_reassemble: bool,
    pub timestamp: u64, // micro sec
}

impl<'a> PayloadReader<'a> {
    pub fn get(&self) -> Option<TcpPayload> {
        self.peek(0)
    }

    /*
        对于 SingleBuffer 来说, 这会改变缓冲区的 buffer 里 TcpFragementMeta 的值,下一次获取数据的时候就会直接从这次的连续数据开始,例如
        ** f1 false 表示 第一帧,is_parsed = false
        | f1 false | f2 false | f3 fasle |
        get() 只会得到第一帧的数据,当 move_next() 后,

        | f1 true | f2 false | f3 fasle |
        get() 会返回 f1 + f2 的数据,并且当连续的帧发生变化后

        | f1 true | f2 false | f3 fasle | f4 false |
        下一次 PayloadReader::get() 依然是从 f1 + f2 的数据开始

        skip_head 后会跳过一帧, 当调用 skip_head 后,get() 只返回 f2

        frame_start 对应 peek(0)/get() 起始读取位置,
        frame off   对应 peek(0)/get() 结束位置,
        peek(0)/get() 就是读取 [frame_start, frame_off] 的数据

    */
    pub fn move_next(&mut self) {
        match &mut self.payload {
            Payload::MetaPacket(_) => {
                if self.buffer_idx == 0 {
                    self.buffer_idx += 1;
                }
            }
            Payload::InFlightBuffer(_, frames) => {
                if self.tcp_frame_off == frames.len() {
                    return;
                }
                let frame = frames.get_mut(self.tcp_frame_off).unwrap();
                frame.is_parsed = true;
                self.tcp_frame_off += 1;
                self.payload_off += frame.payload_len;
            }
            Payload::FlushedBuffer(ref mut buffer) => {
                if self.buffer_idx == buffer.len() {
                    return;
                }
                let (_, tcp_frames) = buffer.get_mut(self.buffer_idx).unwrap();
                let frame = tcp_frames.get_mut(self.tcp_frame_off).unwrap();
                frame.is_parsed = true;
                self.tcp_frame_off += 1;
                self.payload_off += frame.payload_len;
                if self.tcp_frame_off == tcp_frames.len() {
                    self.tcp_frame_off = 0;
                    self.tcp_frame_start = 0;
                    self.payload_off = 0;
                    self.payload_start = 0;
                    self.buffer_idx += 1;
                }
            }
        }
    }

    /*
        skip_head 必须确保 skip 后的帧不能超过 tcp_frame_start,也就是必须先调用 move_nexe() 再调用 skip_head_frame()

        | f1 true | f2 false | f3 false |
        当调用 skip_head_frame 前, peek(0) 返回 f1+f2

        调用 move_nexe + skip_head_frame 后会跳过 f1, peek(0) 返回 f2, peek(1) 返回 f2+f3

    */
    pub fn skip_head(&mut self) -> bool {
        match &mut self.payload {
            Payload::MetaPacket(_) => {
                if self.buffer_idx == 0 {
                    self.buffer_idx += 1;
                    return true;
                }
                false
            }
            Payload::InFlightBuffer(_, frames) => {
                if self.tcp_frame_start < self.tcp_frame_off {
                    self.payload_start += frames.get(self.tcp_frame_start).unwrap().payload_len;
                    self.tcp_frame_start += 1;
                    return true;
                }
                false
            }
            // skip 仅针对当前连续数据
            Payload::FlushedBuffer(buffer) => {
                if self.tcp_frame_start < self.tcp_frame_off {
                    let (_, tcp_frames) = buffer.get(self.buffer_idx).unwrap();
                    self.payload_start += tcp_frames.get(self.tcp_frame_start).unwrap().payload_len;
                    self.tcp_frame_start += 1;
                    return true;
                }
                false
            }
        }
    }

    // 将读取 start 直接跳到 off, 然后 off 置 0, 相当与丢弃所有 从 frame_start 开始所有 is_parsed = true 的数据
    pub fn skip_to_read_end(&mut self) {
        for _ in self.tcp_frame_start..self.tcp_frame_start + self.tcp_frame_off {
            self.skip_head();
        }
    }

    pub fn peek(&self, n: usize) -> Option<TcpPayload> {
        match &self.payload {
            Payload::MetaPacket(p) => {
                if self.buffer_idx + n > 0 {
                    None
                } else {
                    Some(p.clone())
                }
            }
            Payload::InFlightBuffer(buffer, tcp_frames) => {
                if self.tcp_frame_off + n >= tcp_frames.len() {
                    return None;
                }
                let mut payload_off = self.payload_off;
                for i in (&tcp_frames[self.tcp_frame_off..self.tcp_frame_off + n + 1]).iter() {
                    payload_off += i.payload_len;
                }
                Some(TcpPayload {
                    payload: &(buffer.to_slice()[self.payload_start..payload_off]),
                    seq: tcp_frames[self.tcp_frame_start].seq,
                    cap_seq:tcp_frames[self.tcp_frame_start].cap_seq,
                    can_reassemble: true,
                    timestamp: tcp_frames[self.tcp_frame_start].timestamp,
                })
            }

            // MultiBuffer 仅 peek 当前连续数据
            Payload::FlushedBuffer(buffer) => {
                if self.buffer_idx == buffer.len() {
                    return None;
                }
                let (buf, tcp_frames) = buffer.get(self.buffer_idx).unwrap();
                if self.tcp_frame_off + n >= tcp_frames.len() {
                    return None;
                }
                let mut payload_off = self.payload_off;
                for i in (&tcp_frames[self.tcp_frame_off..self.tcp_frame_off + n + 1]).iter() {
                    payload_off += i.payload_len;
                }
                Some(TcpPayload {
                    payload: &buf.as_slice()[self.payload_start..payload_off],
                    seq: tcp_frames[self.tcp_frame_start].seq,
                    cap_seq:tcp_frames[self.tcp_frame_start].cap_seq,
                    can_reassemble: self.tcp_frame_off + n < tcp_frames.len(),
                    timestamp: tcp_frames[self.tcp_frame_start].timestamp,
                })
            }
        }
    }

    // 仅 SingleBuffer 有意义
    pub fn get_current_frame_idx(&self) -> Option<usize> {
        match &self.payload {
            Payload::InFlightBuffer(_, f) => Some(self.tcp_frame_off.min(f.len() - 1)),
            _ => None,
        }
    }

    // 仅 SingleBuffer 有意义
    pub fn get_skip_frame_len(&self) -> Option<usize> {
        match &self.payload {
            Payload::InFlightBuffer(_, _) => Some(self.tcp_frame_start),
            _ => None,
        }
    }
}
