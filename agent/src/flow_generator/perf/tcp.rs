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

use std::fmt;
use std::sync::{atomic::Ordering, Arc};

use bitflags::bitflags;
use log::debug;

use super::{FlowPerfCounter, L4FlowPerf, ART_MAX};

use crate::{
    common::{
        enums::TcpFlags,
        flow::{FlowPerfStats, L4Protocol},
        lookup_key::LookupKey,
        meta_packet::{MetaPacket, MetaPacketTcpHeader, ProtocolData},
        Timestamp,
    },
    flow_generator::error::{Error, Result},
};

const SRT_MAX: Timestamp = Timestamp::from_secs(10);
const RTT_FULL_MAX: Timestamp = Timestamp::from_secs(30);
const RTT_MAX: Timestamp = Timestamp::from_secs(30);

fn adjust_rtt(d: Timestamp, max: Timestamp) -> Timestamp {
    if d > max {
        Timestamp::ZERO
    } else {
        d
    }
}

const WIN_SCALE_MAX: u8 = 14;
const WIN_SCALE_MASK: u8 = 0x0f;
const WIN_SCALE_FLAG: u8 = 0x80;
const WIN_SCALE_UNKNOWN: u8 = 0x40;

bitflags! {
    struct ContinuousFlags: u8 {
        const DISCONTINUOUS = 0x00;
        const LT_CONTINUOUS = 0x01;
        const GTE_CONTINUOUS = 0x10;
        const BOTH_CONTINUOUS = Self::LT_CONTINUOUS.bits | Self::GTE_CONTINUOUS.bits;
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PacketSeqType {
    Error,
    Retrans,
    NotCare,
    Merge,
    Discontinuous,
    Continuous,
    BothContinuous,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SeqSegment {
    // 避免乱序，识别重传
    pub seq: u32,
    pub len: u32,
}

const SEQ_LIST_MAX_LEN: usize = 16;

#[derive(Default)]
pub(crate) struct SessionPeer {
    seq_list: [SeqSegment; SEQ_LIST_MAX_LEN],
    seq_list_len: isize,

    timestamp: Timestamp,
    first_handshake_timestamp: Timestamp, // Client: First SYN; Server: First SYN_ACK

    seq_threshold: u32, // fast syn_retrans check
    seq: u32,
    payload_len: u32,
    win_size: u16,
    win_scale: u8,

    syn_transmitted: bool,

    is_handshake_ack_packet: bool,
    srt_calculable: bool,
    rtt_calculable: bool,
    art_calculable: bool,

    rtt_full_precondition: bool, // rtt计算前置条件，SYN包在SYN/ACK包之前到达
    rtt_full_calculable: bool,   // rtt计算触发标志，完成计算后需reset
}

impl SessionPeer {
    const SEQ_NUMBER_LOW_THRESHOLD: u32 = 0x40000000;
    const SEQ_NUMBER_HIGH_THRESHOLD: u32 = 0xc0000000;

    fn is_sync_ack_ack_packet(&self, p: &MetaPacket) -> bool {
        if let ProtocolData::TcpHeader(tcp_data) = &p.protocol_data {
            return p.is_ack() && tcp_data.ack == self.seq_threshold;
        }
        false
    }

    fn is_reply_packet(&self, p: &MetaPacket) -> bool {
        if let ProtocolData::TcpHeader(tcp_data) = &p.protocol_data {
            return tcp_data.ack == self.seq.overflowing_add(self.payload_len).0;
        }
        false
    }

    fn is_next_packet(&self, p: &MetaPacket) -> bool {
        if let ProtocolData::TcpHeader(tcp_data) = &p.protocol_data {
            return tcp_data.seq == self.seq.overflowing_add(self.payload_len).0;
        }
        false
    }

    // merge array[index+1] into array[index]
    // 忽略调sequence最小的2个node之间的间隔,相当于认为包已收到
    // 其带来的影响是，包被误认为是重传
    fn merge_seq_list(&mut self, index: usize) {
        assert!((index as isize) + 1 < self.seq_list_len);
        let (left, right) = self.seq_list.split_at_mut(index + 1);
        let gte = &mut left[index];
        let lt = &mut right[0];
        gte.len = gte.seq.wrapping_sub(lt.seq).wrapping_add(gte.len);
        gte.seq = lt.seq;
        // 合并后，需要reset被合并的node
        *lt = SeqSegment::default();

        // 仅当被合并node不是最后一个node时，需要将被合并node之后的node往前移一位
        if (index as isize) < self.seq_list_len - 2 {
            self.seq_list[index + 1..self.seq_list_len as usize].rotate_left(1);
        }
        self.seq_list_len -= 1;
    }

    // insert node to array[index]
    fn insert_seq_segment(&mut self, index: usize, seg: SeqSegment) {
        // 当插入的位置非末尾时，需将插入位置到末尾的所有node往后移一位
        // 同时，不会存在，当p.arraySize==16时，执行insert操作的情况，
        // 因为，当p.arraySize>=16时，需立即执行merge操作，使得p.arraySize始终<=15
        if (index as isize) < self.seq_list_len {
            self.seq_list[index..].rotate_right(1);
        }
        self.seq_list[index] = seg;
        self.seq_list_len += 1;
    }

    // 检查当前segment与array中seq最大的segment的距离
    fn check_seq_segment(&mut self, seg: SeqSegment) -> bool {
        // 检查seq是否循环，忽略循环包
        if seg.seq.wrapping_add(seg.len) < seg.seq {
            return false;
        }

        if self.seq_list_len <= 0 {
            self.insert_seq_segment(0, seg);
            return false;
        }

        // array倒序排序，故最大的seq范围节点index为0
        let last_index = 0usize;
        // 前一个包在seq范围的高3/4, 当前包在seq范围的低1/4
        // 意味着seq已循环，需清空array
        if seg.seq < Self::SEQ_NUMBER_LOW_THRESHOLD
            && self.seq_list[last_index].seq + self.seq_list[last_index].len
                > Self::SEQ_NUMBER_HIGH_THRESHOLD
        {
            // 清空list
            self.seq_list = Default::default();
            self.seq_list_len = 0;
            // 插入当前包
            self.insert_seq_segment(0, seg);
            return false;
        }

        // 前一个包在seq范围的低1/4, 当前包在seq范围的高3/4
        // 意味着之前的包重传或乱序了，忽略这类包
        if seg.seq > Self::SEQ_NUMBER_HIGH_THRESHOLD
            && self.seq_list[last_index].seq + self.seq_list[last_index].len
                < Self::SEQ_NUMBER_LOW_THRESHOLD
        {
            // 忽略当前包
            return false;
        }

        true
    }

    // 因数组中每个segment.seq默认为0，故seq_list为降序数组；直至找到seq大于或等于seg.seq的节点
    // 返回值
    fn search(
        &mut self,
        seg: &SeqSegment,
    ) -> (Option<&mut SeqSegment>, Option<&mut SeqSegment>, usize) {
        if self.seq_list_len == 0 {
            return (None, None, 0);
        }
        let mut index = self.seq_list_len as usize;
        for (i, s) in self.seq_list[..self.seq_list_len as usize]
            .iter()
            .enumerate()
        {
            if seg.seq > s.seq {
                // 查找node在list中的位置
                index = i;
                break;
            }
        }
        if index == 0 {
            (Some(&mut self.seq_list[index]), None, index)
        } else if index == self.seq_list_len as usize {
            (None, Some(&mut self.seq_list[index - 1]), index)
        } else {
            let (left, right) = self.seq_list.split_at_mut(index);
            (Some(&mut right[0]), Some(&mut left[index - 1]), index)
        }
    }

    // 用于判断SeqSegment是否与lt或gte连续
    // 如果把SeqSegment看作是sequence number的集合，continuous可认为是node与lt或gte相
    fn check_and_update_continuous_segment(
        lt: &mut Option<&mut SeqSegment>,
        gte: &mut Option<&mut SeqSegment>,
        seg: &SeqSegment,
    ) -> ContinuousFlags {
        let mut flag = ContinuousFlags::DISCONTINUOUS;

        if let Some(lt) = lt {
            if lt.seq + lt.len == seg.seq {
                lt.len += seg.len;
                flag |= ContinuousFlags::LT_CONTINUOUS;
            }
        }

        if let Some(gte) = gte {
            if seg.seq + seg.len == gte.seq {
                gte.seq = seg.seq;
                gte.len += seg.len;
                flag |= ContinuousFlags::GTE_CONTINUOUS;
            }
        }

        flag
    }

    fn check_retrans(base: &SeqSegment, seg: &SeqSegment) -> bool {
        seg.seq >= base.seq && base.seq + base.len >= seg.seq + seg.len
    }

    fn is_retrans_segment(
        lt: &Option<&mut SeqSegment>,
        gte: &Option<&mut SeqSegment>,
        seg: &SeqSegment,
    ) -> bool {
        if let Some(lt) = lt {
            Self::check_retrans(lt, seg)
        } else if let Some(gte) = gte {
            Self::check_retrans(gte, seg)
        } else {
            unreachable!()
        }
    }

    // 如果把SeqSegment看作是sequence number的集合，error可认为是seg与lt或gte相交
    fn is_error_segment(
        lt: &Option<&mut SeqSegment>,
        gte: &Option<&mut SeqSegment>,
        seg: &SeqSegment,
    ) -> bool {
        if let Some(gte) = gte {
            if seg.seq < gte.seq && seg.seq + seg.len > gte.seq
                || seg.seq + seg.len > gte.seq + gte.len
            {
                return true;
            }
        }
        if let Some(lt) = lt {
            if lt.seq + lt.len > seg.seq {
                return true;
            }
        }
        false
    }

    // 根据seqNumber判断包重传,连续,不连续
    // 合并连续seqNumber
    // 不连续则添加新节点, 构建升序链表
    fn assert_seq_number(
        &mut self,
        header: &MetaPacketTcpHeader,
        payload_len: u16,
    ) -> PacketSeqType {
        if payload_len == 0 || header.seq == 0 {
            return PacketSeqType::NotCare;
        }

        let seg = SeqSegment {
            seq: header.seq,
            len: payload_len as u32,
        };
        if !self.check_seq_segment(seg) {
            return PacketSeqType::NotCare;
        }

        let (mut lt, mut gte, index) = self.search(&seg);
        if Self::is_retrans_segment(&lt, &gte, &seg) {
            PacketSeqType::Retrans
        } else if Self::is_error_segment(&lt, &gte, &seg) {
            PacketSeqType::Error
        } else {
            match Self::check_and_update_continuous_segment(&mut lt, &mut gte, &seg) {
                ContinuousFlags::DISCONTINUOUS => {
                    self.insert_seq_segment(index, seg);
                    if self.seq_list_len as usize >= SEQ_LIST_MAX_LEN {
                        self.merge_seq_list(SEQ_LIST_MAX_LEN - 2);
                        PacketSeqType::Merge
                    } else {
                        PacketSeqType::Discontinuous
                    }
                }
                ContinuousFlags::BOTH_CONTINUOUS => {
                    self.merge_seq_list(index - 1);
                    PacketSeqType::BothContinuous
                }
                _ => PacketSeqType::Continuous,
            }
        }
    }

    // 在TCP_STATE_ESTABLISHED阶段更新数据
    fn update_data(&mut self, p: &MetaPacket) {
        let tcp_data = if let ProtocolData::TcpHeader(tcp_data) = &p.protocol_data {
            tcp_data
        } else {
            unreachable!();
        };
        self.timestamp = p.lookup_key.timestamp.into();
        self.payload_len = p.payload_len as u32;
        if tcp_data.flags.contains(TcpFlags::SYN) {
            self.payload_len = 1;
        }
        self.seq = tcp_data.seq;
        self.win_size = tcp_data.win_size;
        // winScale不能在这里更新p.winScale = tcpHeader.WinScale
    }
}

impl fmt::Display for SessionPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "timestamp: {:?}, seq: {}, payload_len: {}, win_size: {}, win_scale: {}, srt_calculable: {}, art_calculable: {}, seq_list: {:?}",
            self.timestamp, self.seq, self.payload_len, self.win_size, self.win_scale, self.srt_calculable, self.art_calculable, &self.seq_list[..self.seq_list_len as usize])
    }
}

#[derive(Default)]
pub(crate) struct PerfControl(SessionPeer, SessionPeer);

#[derive(Default, Debug, PartialEq, Eq)]
struct TimeStats {
    pub count: u32,
    pub sum: Timestamp,
    pub max: Timestamp,
    pub updated: bool,
}

impl TimeStats {
    fn update(&mut self, d: Timestamp) {
        self.count += 1;
        self.sum += d;
        if self.max < d {
            self.max = d;
        }
        self.updated = true;
    }
}

// art---Application Response Time
// 现有3个连续包PSH/ACK--ACK--PSH/ACK,其中第一个包是client端的请求包，
// 后2个包是server端的应答包，art表示后2个包之间的时间间隔
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct PerfData {
    rtt_0: TimeStats, // The time difference between the first SYN and the last SYN_ACK
    rtt_1: TimeStats, // The time difference between the first SYN_ACK and the last ACK
    art_0: TimeStats,
    art_1: TimeStats,
    srt_0: TimeStats,
    srt_1: TimeStats,
    cit: TimeStats,

    // flow数据
    retrans_sum: u32,
    rtt_full: Timestamp,

    // 包括syn重传
    retrans_0: u32,
    retrans_1: u32,
    // 计入retrans
    retrans_syn_0: u32,
    retrans_syn_1: u32,
    // 未使用
    psh_urg_count_0: u32,
    psh_urg_count_1: u32,

    zero_win_count_0: u32,
    zero_win_count_1: u32,

    // SYN SYN_ACK count
    syn: u32,
    synack: u32,

    // Retran SYN SYN_ACK count
    retrans_syn: u32,
    retrans_synack: u32,

    updated: bool,
}

impl PerfData {
    // fpd for first packet direction

    // FIXME: art,rtt均值计算方法，需要增加影响因子
    // 计算art值
    fn calc_art(&mut self, d: Timestamp, fpd: bool) {
        if fpd {
            self.art_0.update(d);
        } else {
            self.art_1.update(d);
        }
        self.updated = true;
    }

    // 计算srt值
    fn calc_srt(&mut self, d: Timestamp, fpd: bool) {
        if fpd {
            self.srt_0.update(d);
        } else {
            self.srt_1.update(d);
        }
        self.updated = true;
    }

    fn calc_rtt_full(&mut self, d: Timestamp) {
        self.rtt_full = d;
        self.updated = true;
    }

    fn calc_rtt(&mut self, d: Timestamp, fpd: bool) {
        if fpd {
            self.rtt_0.update(d);
        } else {
            self.rtt_1.update(d);
        }
        self.updated = true;
    }

    fn calc_retrans_syn(&mut self, fpd: bool) {
        if fpd {
            self.retrans_syn_0 += 1;
        } else {
            self.retrans_syn_1 += 1;
        }
        self.calc_retrans(fpd);
        self.updated = true;
    }

    fn calc_retrans(&mut self, fpd: bool) {
        if fpd {
            self.retrans_0 += 1;
        } else {
            self.retrans_1 += 1;
        }
        self.retrans_sum += 1;
        self.updated = true;
    }

    fn calc_zero_win(&mut self, fpd: bool) {
        if fpd {
            self.zero_win_count_0 += 1;
        } else {
            self.zero_win_count_1 += 1;
        }
        self.updated = true;
    }

    fn calc_psh_urg(&mut self, fpd: bool) {
        if fpd {
            self.psh_urg_count_0 += 1;
        } else {
            self.psh_urg_count_1 += 1;
        }
        self.updated = true;
    }

    fn calc_syn(&mut self) {
        self.syn += 1;
        self.updated = true;
    }

    fn calc_synack(&mut self) {
        self.synack += 1;
        self.updated = true;
    }

    fn calc_retran_syn(&mut self) {
        self.retrans_syn += 1;
        self.updated = true;
    }

    fn calc_retrans_synack(&mut self) {
        self.retrans_synack += 1;
        self.updated = true;
    }

    fn calc_cit(&mut self, d: Timestamp) {
        self.cit.update(d);
        self.updated = true;
    }

    fn update_perf_stats(&mut self, stats: &mut FlowPerfStats, flow_reversed: bool) {
        if !self.updated {
            return;
        }
        self.updated = false;

        let stats = &mut stats.tcp;
        stats.counts_peers[0].retrans_count = self.retrans_0;
        stats.counts_peers[1].retrans_count = self.retrans_1;
        stats.total_retrans_count = self.retrans_sum;
        stats.counts_peers[0].zero_win_count = self.zero_win_count_0;
        stats.counts_peers[1].zero_win_count = self.zero_win_count_1;

        stats.syn_count = self.syn;
        stats.synack_count = self.synack;
        stats.retrans_syn_count = self.retrans_syn;
        stats.retrans_synack_count = self.retrans_synack;

        stats.rtt = self.rtt_full.as_micros() as u32;

        if !flow_reversed {
            if self.art_1.updated {
                stats.art_max = self.art_1.max.as_micros() as u32;
                stats.art_sum = self.art_1.sum.as_micros() as u32;
                stats.art_count = self.art_1.count;
            }
            if self.srt_1.updated {
                stats.srt_max = self.srt_1.max.as_micros() as u32;
                stats.srt_sum = self.srt_1.sum.as_micros() as u32;
                stats.srt_count = self.srt_1.count;
            }
        } else {
            if self.art_0.updated {
                stats.art_max = self.art_0.max.as_micros() as u32;
                stats.art_sum = self.art_0.sum.as_micros() as u32;
                stats.art_count = self.art_0.count;
            }
            if self.srt_0.updated {
                stats.srt_max = self.srt_0.max.as_micros() as u32;
                stats.srt_sum = self.srt_0.sum.as_micros() as u32;
                stats.srt_count = self.srt_0.count;
            }
            stats.reverse();
        }

        if self.rtt_0.updated {
            stats.rtt_client_max = self.rtt_0.max.as_micros() as u32;
            stats.rtt_client_sum = self.rtt_0.sum.as_micros() as u32;
            stats.rtt_client_count = self.rtt_0.count;
        }

        if self.rtt_1.updated {
            stats.rtt_server_max = self.rtt_1.max.as_micros() as u32;
            stats.rtt_server_sum = self.rtt_1.sum.as_micros() as u32;
            stats.rtt_server_count = self.rtt_1.count;
        }

        if self.cit.updated {
            stats.cit_max = self.cit.max.as_micros() as u32;
            stats.cit_sum = self.cit.sum.as_micros() as u32;
            stats.cit_count = self.cit.count;
        }
    }
}

pub struct TcpPerf {
    ctrl_info: PerfControl,
    perf_data: PerfData,
    counter: Arc<FlowPerfCounter>,
    handshaking: bool,
}

impl TcpPerf {
    pub fn new(counter: Arc<FlowPerfCounter>) -> Self {
        Self {
            ctrl_info: Default::default(),
            perf_data: Default::default(),
            counter,
            handshaking: false,
        }
    }

    pub fn reset(&mut self) {
        self.ctrl_info = Default::default();
        self.perf_data = Default::default();
        self.handshaking = false;
    }

    // fpd for first packet direction
    fn is_invalid_retrans_packet(&mut self, p: &MetaPacket, fpd: bool) -> (bool, bool) {
        let tcp_data = if let ProtocolData::TcpHeader(tcp_data) = &p.protocol_data {
            tcp_data
        } else {
            unreachable!();
        };
        let (same_dir, oppo_dir) = if fpd {
            (&mut self.ctrl_info.0, &mut self.ctrl_info.1)
        } else {
            (&mut self.ctrl_info.1, &mut self.ctrl_info.0)
        };
        if p.is_syn() {
            if same_dir.seq_threshold == 0 {
                // first SYN
                same_dir.seq_threshold = tcp_data.seq + 1;
                same_dir.first_handshake_timestamp = p.lookup_key.timestamp.into();
                self.handshaking = true;
            } else if same_dir.syn_transmitted {
                self.perf_data.calc_retrans_syn(fpd);
                self.perf_data.calc_retran_syn();
            }
            same_dir.syn_transmitted = true;
            return (false, false);
        }

        if p.is_syn_ack() {
            if same_dir.seq_threshold == 0 {
                // first
                same_dir.first_handshake_timestamp = p.lookup_key.timestamp.into();
                same_dir.seq_threshold = tcp_data.seq + 1;
                if oppo_dir.seq_threshold == 0 {
                    // no syn before first syn/ack
                    oppo_dir.seq_threshold = tcp_data.ack;
                } else {
                    oppo_dir.rtt_full_precondition = true;
                }
            } else {
                self.perf_data.calc_retrans_syn(fpd);
                self.perf_data.calc_retrans_synack();
            }
            return (false, false);
        }

        if p.is_ack() {
            // It is impossible to distinguish retransmission between ACK and ACK
            // keepalive. To avoid misunderstanding, retransmission of pure ACK
            // ==================================================================
            // 无法区分 ACK 重传和 ACK Keepalive，为了避免误解不计算纯 ACK 包的重传。
            return (false, false);
        }

        if !p.has_valid_payload() {
            return (false, false);
        }

        // 连接建立后，即ESTABLISHED阶段，用SeqArray判断包重传
        match same_dir.assert_seq_number(tcp_data, p.payload_len) {
            PacketSeqType::Retrans => {
                // established retrans
                self.perf_data.calc_retrans(fpd);
                (false, true)
            }
            PacketSeqType::Error => {
                self.counter
                    .invalid_packet_count
                    .fetch_add(1, Ordering::Relaxed);
                (true, false)
            }
            _ => (false, false),
        }
    }

    fn is_interested_tcp_flags(flags: TcpFlags) -> bool {
        if flags.contains(TcpFlags::SYN) {
            if flags.intersects(TcpFlags::FIN | TcpFlags::RST) {
                return false;
            }
        } else {
            if !flags.intersects(TcpFlags::ACK | TcpFlags::RST) {
                return false;
            }
        }

        if !flags.contains(TcpFlags::ACK) {
            if flags.intersects(TcpFlags::PSH | TcpFlags::FIN | TcpFlags::URG) {
                return false;
            }
        }

        // flow perf do not take care
        if flags.intersects(TcpFlags::FIN | TcpFlags::RST) {
            return false;
        }

        true
    }

    fn is_handshake_ack_packet(
        _same_dir: &mut SessionPeer,
        oppo_dir: &mut SessionPeer,
        p: &MetaPacket,
    ) -> bool {
        if let ProtocolData::TcpHeader(tcp_data) = &p.protocol_data {
            return p.is_ack() && oppo_dir.seq_threshold == tcp_data.ack;
        }
        false
    }

    fn flow_opening(&mut self, p: &MetaPacket, fpd: bool) -> bool {
        let (same_dir, oppo_dir) = if fpd {
            (&mut self.ctrl_info.0, &mut self.ctrl_info.1)
        } else {
            (&mut self.ctrl_info.1, &mut self.ctrl_info.0)
        };

        if same_dir.rtt_calculable {
            if oppo_dir.is_reply_packet(p) {
                // rtt0 = Time(Last SYN_ACK) - Time(First SYN)
                // rtt1 = Time(Last ACK) - Time(First SYN_ACK)
                // Example:
                // Packet：
                // - A: SYN
                // - B: SYN
                // - C: SYN_ACK
                // - D: SYN_ACK
                // - E: ACK
                // - F: ACK
                // rtt0: TimeStats{Count: 2, Sum: (C-A)+(D-A), Max: D-A}
                // rtt1: TimeStats{Count: 2, Sum: (E-C)+(F-C), Max: F-C}
                if (Self::is_handshake_ack_packet(same_dir, oppo_dir, p) || p.is_syn_ack())
                    && !oppo_dir.first_handshake_timestamp.is_zero()
                {
                    let rtt = adjust_rtt(
                        (p.lookup_key.timestamp - oppo_dir.first_handshake_timestamp).into(),
                        RTT_MAX,
                    );
                    if !rtt.is_zero() {
                        self.perf_data.calc_rtt(rtt, fpd);
                    }
                }
            }
        }
        if same_dir.rtt_full_calculable {
            if oppo_dir.is_sync_ack_ack_packet(p) {
                let rtt_full = adjust_rtt(
                    (p.lookup_key.timestamp - same_dir.first_handshake_timestamp).into(),
                    RTT_FULL_MAX,
                );
                if !rtt_full.is_zero() {
                    self.perf_data.calc_rtt_full(rtt_full);
                }
            }
        }

        let tcp_data = if let ProtocolData::TcpHeader(tcp_data) = &p.protocol_data {
            tcp_data
        } else {
            unreachable!();
        };
        let is_opening = if p.is_syn() || p.is_syn_ack() {
            if tcp_data.win_scale > 0 {
                same_dir.win_scale = WIN_SCALE_FLAG | tcp_data.win_scale.min(WIN_SCALE_MAX);
            }

            same_dir.rtt_calculable = true;
            same_dir.srt_calculable = false;
            same_dir.art_calculable = false;

            oppo_dir.rtt_calculable = true;
            oppo_dir.srt_calculable = false;
            oppo_dir.art_calculable = false;

            if p.is_syn_ack() && oppo_dir.rtt_full_precondition {
                oppo_dir.rtt_full_calculable = true;
            }

            true
        } else {
            if !p.is_ack() {
                same_dir.rtt_calculable = false;
                oppo_dir.rtt_calculable = false;
                same_dir.rtt_full_calculable = false;
            }
            p.is_ack()
        };

        if Self::is_handshake_ack_packet(same_dir, oppo_dir, p) {
            same_dir.is_handshake_ack_packet = true;
        }

        is_opening
    }

    // 根据flag, direction, payload_len或PSH, SEQ, ACK重建状态机
    // assume: 包已经过预处理，无异常flag包，也没有与功能无关包（不关心报文）
    fn flow_established(&mut self, p: &MetaPacket, fpd: bool) {
        let (same_dir, oppo_dir) = if fpd {
            (&mut self.ctrl_info.0, &mut self.ctrl_info.1)
        } else {
            (&mut self.ctrl_info.1, &mut self.ctrl_info.0)
        };

        // srt--用连续的PSH/ACK(payload_len>0)和反向ACK(payload_len==0)计算srt值
        if same_dir.srt_calculable {
            if p.is_ack() && oppo_dir.is_reply_packet(p) {
                let srt = adjust_rtt(
                    (p.lookup_key.timestamp - oppo_dir.timestamp).into(),
                    SRT_MAX,
                );
                if !srt.is_zero() {
                    self.perf_data.calc_srt(srt, fpd);
                }
            }
        }

        // art--用连续的PSH/ACK(payload_len>0)和ACK(payload_len==0)[可选]、PSH/ACK(payload_len>0)计算art值
        if same_dir.art_calculable {
            if p.has_valid_payload() && same_dir.is_next_packet(p) {
                let art = adjust_rtt(
                    (p.lookup_key.timestamp - oppo_dir.timestamp).into(),
                    ART_MAX,
                );
                if !art.is_zero() {
                    self.perf_data.calc_art(art, fpd);
                }
            }
        }

        if p.is_ack() {
            // 收到ACK包，仅能用于同向判断是否计算art
            same_dir.srt_calculable = false;

            oppo_dir.srt_calculable = false;
            oppo_dir.art_calculable = false;
        } else if p.is_psh_ack() {
            // 收到PSH/ACK包，仅可用于反向判断是否计算rtt, art
            same_dir.srt_calculable = false;
            same_dir.art_calculable = false;

            oppo_dir.srt_calculable = true;
            oppo_dir.art_calculable = true;
        } else {
            // 其它包，均为无效包，reset所有前置条件
            same_dir.srt_calculable = false;
            same_dir.art_calculable = false;

            oppo_dir.srt_calculable = false;
            oppo_dir.art_calculable = false;
        }
        let tcp_data = if let ProtocolData::TcpHeader(tcp_data) = &p.protocol_data {
            tcp_data
        } else {
            unreachable!();
        };
        // zero_win, psh_urg_count_0
        let mut win_size = tcp_data.win_size as u32;
        if same_dir.win_scale & oppo_dir.win_scale & WIN_SCALE_FLAG > 0 {
            win_size <<= (same_dir.win_scale & WIN_SCALE_MASK) as u32;
        }
        // win_size == 0 or zero window
        if win_size == 0 {
            self.perf_data.calc_zero_win(fpd);
        }

        // PSH/URG
        if tcp_data.flags & TcpFlags::MASK == TcpFlags::PSH_ACK_URG {
            self.perf_data.calc_psh_urg(fpd);
        }
        // calculate client waiting time
        //
        // 客户端发包 payload > 1（不能等于1，因为有可能是 heartbeat）,
        // - client前一个包是syn-ack-ack，那么idle_time = current_time - max(previouse_client_packet_time, previouse_server_packet_time)
        // - idel_time = current_time - previouse_server_packet_time
        // =================
        // The client sends the packet payload > 1 (cannot be equal to 1, because it may be heartbeat)
        // - the previous packet of the client is syn-ack-ack, then idle_time = current_time - max(previouse_client_packet_time, previouse_server_packet_time)
        // - idel_time = current_time - previouse_server_packet_time
        if fpd && p.is_psh_ack() && p.payload_len > 1 {
            if same_dir.is_handshake_ack_packet {
                same_dir.is_handshake_ack_packet = false;
                let d = p.lookup_key.timestamp - same_dir.timestamp.max(oppo_dir.timestamp);
                self.perf_data.calc_cit(d.into());
            } else if oppo_dir.payload_len > 1
                && (same_dir.payload_len <= 1 || oppo_dir.timestamp > same_dir.timestamp)
            {
                let d = p.lookup_key.timestamp - oppo_dir.timestamp;
                self.perf_data.calc_cit(d.into());
            }
        }
    }

    // 根据flag, direction, payload_len或PSH, SEQ, ACK重建状态机
    // assume: 包已经过预处理，无异常flag包，也没有与功能无关包（不关心报文）
    fn calculate(&mut self, p: &MetaPacket, fpd: bool) -> bool {
        let (is_invalid, is_retrans) = self.is_invalid_retrans_packet(p, fpd);
        if is_invalid {
            self.ctrl_info.0.srt_calculable = false;
            self.ctrl_info.0.art_calculable = false;
            self.ctrl_info.1.srt_calculable = false;
            self.ctrl_info.1.art_calculable = false;
            return is_retrans;
        }

        // 计算RTT
        if self.handshaking {
            self.handshaking = self.flow_opening(p, fpd);
        }

        // 计算ART
        if !self.handshaking {
            self.flow_established(p, fpd);
        }

        // calculate syn/synack count
        if p.is_syn() {
            // calculate established state retran syn
            if is_retrans {
                self.perf_data.calc_retran_syn();
            }
            self.perf_data.calc_syn();
        }

        if p.is_syn_ack() {
            // calculate established state retran synack
            if is_retrans {
                self.perf_data.calc_retrans_synack();
            }
            self.perf_data.calc_synack();
        }

        is_retrans
    }

    // 异常flag判断，方向识别，payload_len计算等
    // 去除功能不相关报文
    fn is_interested_packet(&self, p: &MetaPacket) -> bool {
        let tcp_data = if let ProtocolData::TcpHeader(tcp_data) = &p.protocol_data {
            tcp_data
        } else {
            unreachable!();
        };
        if tcp_data.data_offset == 0 {
            // invalid tcp header or ip fragment
            return false;
        }

        if !Self::is_interested_tcp_flags(tcp_data.flags) {
            self.counter
                .ignored_packet_count
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }

        true
    }
}

impl L4FlowPerf for TcpPerf {
    fn parse(&mut self, p: &MetaPacket, fpd: bool) -> Result<()> {
        if !self.is_interested_packet(p) {
            self.ctrl_info.0.srt_calculable = false;
            self.ctrl_info.0.art_calculable = false;
            self.ctrl_info.0.rtt_full_precondition = false;
            self.ctrl_info.0.rtt_full_calculable = false;
            self.ctrl_info.1.srt_calculable = false;
            self.ctrl_info.1.art_calculable = false;
            self.ctrl_info.1.rtt_full_precondition = false;
            self.ctrl_info.1.rtt_full_calculable = false;
            return Ok(());
        }

        if p.lookup_key.timestamp < self.ctrl_info.0.timestamp
            || p.lookup_key.timestamp < self.ctrl_info.1.timestamp
        {
            self.counter
                .invalid_packet_count
                .fetch_add(1, Ordering::Relaxed);
            let (same_dir, oppo_dir) = if fpd {
                (&self.ctrl_info.0, &self.ctrl_info.1)
            } else {
                (&self.ctrl_info.1, &self.ctrl_info.0)
            };
            debug!(
                "packet timestamp error, same last: {:?}, opposite last: {:?}, packet: {:?}",
                same_dir.timestamp, oppo_dir.timestamp, p.lookup_key.timestamp
            );
            return Err(Error::InvalidPacketTimestamp);
        }

        let is_retrans = self.calculate(p, fpd);
        if fpd {
            self.ctrl_info.0.update_data(p);
        } else {
            self.ctrl_info.1.update_data(p);
        }
        if is_retrans {
            return Err(Error::RetransPacket);
        }

        Ok(())
    }

    fn data_updated(&self) -> bool {
        let d = &self.perf_data;
        d.updated
    }

    fn copy_and_reset_data(&mut self, flow_reversed: bool) -> FlowPerfStats {
        let mut stats = FlowPerfStats::default();
        stats.l4_protocol = L4Protocol::Tcp;
        self.perf_data.update_perf_stats(&mut stats, flow_reversed);
        self.perf_data = Default::default();
        stats
    }
}

impl fmt::Debug for TcpPerf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "flow ctrl_info: {} {}\nflow perf_data: {:?}",
            self.ctrl_info.0, self.ctrl_info.1, self.perf_data
        )
    }
}

#[doc(hidden)]
pub fn _benchmark_report(perf: &mut TcpPerf) {
    let pd = &mut perf.perf_data;
    pd.art_0.max = Timestamp::from_nanos(100);
    pd.art_0.sum = Timestamp::from_nanos(100);
    pd.art_0.count = 1;
    pd.art_1.max = Timestamp::from_nanos(300);
    pd.art_1.sum = Timestamp::from_nanos(300);
    pd.art_1.count = 1;
    let _ = perf.copy_and_reset_data(false);
    let pd = &mut perf.perf_data;
    pd.art_0.max = Timestamp::from_nanos(200);
    pd.art_0.sum = Timestamp::from_nanos(200);
    pd.art_0.count = 1;
    pd.srt_0.max = Timestamp::from_nanos(1000);
    pd.srt_0.sum = Timestamp::from_nanos(1000);
    pd.srt_0.count = 1;
    let _ = perf.copy_and_reset_data(false);
}

#[doc(hidden)]
pub fn _benchmark_session_peer_seq_no_assert(is_desc: bool) {
    let mut peer = SessionPeer::default();
    if !is_desc {
        for i in 0..SEQ_LIST_MAX_LEN {
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: i as u32 * 10 + 1,
                    ack: 20,
                    ..Default::default()
                },
                10,
            );
        }
    } else {
        for i in (0..=SEQ_LIST_MAX_LEN).rev() {
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: i as u32 * 10 + 1,
                    ack: 20,
                    ..Default::default()
                },
                10,
            );
        }
    }

    // error
    peer.assert_seq_number(
        &MetaPacketTcpHeader {
            seq: SEQ_LIST_MAX_LEN as u32 * 10,
            ack: 20,
            ..Default::default()
        },
        10,
    );

    // retrans
    peer.assert_seq_number(
        &MetaPacketTcpHeader {
            seq: 0,
            ack: 20,
            ..Default::default()
        },
        10,
    );

    // insert 17th node (merge_seq_list_node)
    peer.assert_seq_number(
        &MetaPacketTcpHeader {
            seq: 200,
            ack: 20,
            ..Default::default()
        },
        10,
    );

    // continuous
    peer.assert_seq_number(
        &MetaPacketTcpHeader {
            seq: 10,
            ack: 20,
            ..Default::default()
        },
        1,
    );
}

#[doc(hidden)]
#[derive(Default)]
struct MiniMetaPacket {
    data_offset: u8,
    flags: TcpFlags,
    seq: u32,
    ack: u32,
    timestamp: u64,
    payload_len: u16,
    packet_len: u32,
}

impl<'a> From<MiniMetaPacket> for MetaPacket<'_> {
    fn from(m: MiniMetaPacket) -> Self {
        let mut packet = MetaPacket::empty();
        packet.protocol_data = ProtocolData::TcpHeader(MetaPacketTcpHeader {
            data_offset: m.data_offset,
            flags: m.flags,
            seq: m.seq,
            ack: m.ack,
            ..Default::default()
        });
        packet.lookup_key = LookupKey {
            timestamp: Timestamp::from_secs(m.timestamp),
            ..Default::default()
        };
        packet.payload_len = m.payload_len;
        packet.packet_len = m.packet_len;
        packet
    }
}

#[doc(hidden)]
pub fn _meta_flow_perf_update(perf: &mut TcpPerf) {
    /*
     * rttSum1=1, rttSum0=10: 1SYN -> 2SYN/ACK -> 1ACK ->
     * *art1=4, not rtt: 1ACK/LEN>0 -> 2ACK/LEN>0 -> 2ACK ->
     * srt0=16: 2ACK/LEN>0 -> 1ACK ->
     * art0=70: 1ACK/LEN>0 ->
     * *srt1=100: 2ACK ->
     * *art1=106: 2ACK/LEN>0 ->
     * 非连续: 1ACK(重复) -> 1ACK ->
     * 非连续: 2ACK/LEN>0 -> 2ACK/LEN>0 -> 1ACK(确认前一个包) ->
     */
    // 1SYN
    let packet = MiniMetaPacket {
        flags: TcpFlags::SYN,
        seq: 111,
        ack: 0,
        timestamp: 3333,
        ..Default::default()
    }
    .into();
    perf.parse(&packet, false).unwrap();

    // 2SYN/ACK rttSum1=1
    let packet = MiniMetaPacket {
        flags: TcpFlags::SYN_ACK,
        seq: 1111,
        ack: 112,
        timestamp: 3334,
        ..Default::default()
    }
    .into();
    perf.parse(&packet, true).unwrap();

    // 1ACK rttSum0=10
    let packet = MiniMetaPacket {
        flags: TcpFlags::ACK,
        seq: 112,
        ack: 1112,
        timestamp: 3344,
        ..Default::default()
    }
    .into();
    perf.parse(&packet, false).unwrap();

    // 1ACK/LEN>0 len=100
    let packet = MiniMetaPacket {
        flags: TcpFlags::ACK,
        seq: 112,
        ack: 1112,
        timestamp: 3350,
        payload_len: 100,
        ..Default::default()
    }
    .into();
    perf.parse(&packet, false).unwrap();

    // 2ACK/LEN>0包，len=100 *art1=4
    let packet = MiniMetaPacket {
        flags: TcpFlags::ACK,
        seq: 1112,
        ack: 212,
        timestamp: 3354,
        payload_len: 100,
        ..Default::default()
    }
    .into();
    perf.parse(&packet, true).unwrap();

    // 2ACK 测试连续ACK包, 对RTT计算的影响
    let packet = MiniMetaPacket {
        flags: TcpFlags::ACK,
        seq: 1112,
        ack: 212,
        timestamp: 3358,
        ..Default::default()
    }
    .into();
    perf.parse(&packet, true).unwrap();

    // 2ACK/LEN>0 len=500
    let packet = MiniMetaPacket {
        flags: TcpFlags::PSH_ACK,
        seq: 1212,
        ack: 212,
        timestamp: 3384,
        payload_len: 500,
        ..Default::default()
    }
    .into();
    perf.parse(&packet, true).unwrap();

    // 1ACK srt0=16
    let packet = MiniMetaPacket {
        flags: TcpFlags::ACK,
        seq: 212,
        ack: 1712,
        timestamp: 3400,
        ..Default::default()
    }
    .into();
    perf.parse(&packet, false).unwrap();

    // 1ACK/LEN>0 len=200 art0=70
    let packet = MiniMetaPacket {
        flags: TcpFlags::ACK,
        seq: 212,
        ack: 1712,
        timestamp: 3454,
        payload_len: 200,
        ..Default::default()
    }
    .into();
    perf.parse(&packet, false).unwrap();

    // 2ACK *srt1=100
    let packet = MiniMetaPacket {
        flags: TcpFlags::ACK,
        seq: 1712,
        ack: 412,
        timestamp: 3554,
        ..Default::default()
    }
    .into();
    perf.parse(&packet, true).unwrap();

    // 2ACK/LEN>0 len=300 *art1=106
    let packet = MiniMetaPacket {
        flags: TcpFlags::ACK,
        seq: 1712,
        ack: 412,
        timestamp: 3560,
        payload_len: 300,
        ..Default::default()
    }
    .into();
    perf.parse(&packet, true).unwrap();
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::utils::test::Capture;

    const FILE_DIR: &'static str = "resources/test/flow_generator";

    #[test]
    fn adjust() {
        assert_eq!(adjust_rtt(SRT_MAX, SRT_MAX), SRT_MAX);
        assert_eq!(
            adjust_rtt(SRT_MAX + Timestamp::from_secs(1), SRT_MAX),
            Timestamp::ZERO
        );
        assert_eq!(adjust_rtt(ART_MAX, ART_MAX), ART_MAX);
        assert_eq!(
            adjust_rtt(ART_MAX + Timestamp::from_secs(1), ART_MAX),
            Timestamp::ZERO
        );
    }

    #[test]
    fn handshake() {
        perf_test_helper(
            &vec!["handshake-error.pcap"],
            "handshake-error.result",
            false,
        );
    }

    #[test]
    fn rtt_syn() {
        perf_test_helper(
            &vec!["rtt-syn-2-ack.pcap", "rtt-rtt-2.pcap"],
            "rtt-syn.result",
            false,
        );
    }

    #[test]
    fn rtt_full() {
        perf_test_helper(
            &vec![
                "rtt-200ms-window-update.pcap",
                "client-keep-alive.pcap",
                "syn-retrans.pcap",
                "syn-syn-ack-retrans.pcap",
                "syn-syn-ack-retrans-2.pcap",
                "syn-ack-ack-retrans-and-client-payload.pcap",
                "out-of-order.pcap",
            ],
            "rtt-full.result",
            false,
        );
    }

    #[test]
    fn art() {
        perf_test_helper(
            &vec!["art-continues-payload-len-larger-than-1.pcap"],
            "art.result",
            false,
        );
    }

    #[test]
    fn retrans() {
        perf_test_helper(
            &vec!["xiangdao-retrans.pcap"],
            "xiangdao-retrans.result",
            true,
        );
    }

    #[test]
    fn client_request_timewait_and_syn_synack_count() {
        perf_test_helper(
            &vec!["client_request_timewait_and_syn_synack_count.pcap"],
            "client_request_timewait_and_syn_synack_count.result",
            false,
        )
    }

    #[test]
    fn continuous_seq_segment() {
        // nil, {5, 10}
        let mut seg = SeqSegment { seq: 1, len: 4 };
        let mut right = SeqSegment { seq: 5, len: 10 };
        assert_ne!(
            SessionPeer::check_and_update_continuous_segment(
                &mut None,
                &mut Some(&mut right),
                &mut seg
            ),
            ContinuousFlags::DISCONTINUOUS
        );

        // {51, 5}, nil
        let mut seg = SeqSegment { seq: 56, len: 4 };
        let mut left = SeqSegment { seq: 51, len: 5 };
        assert_ne!(
            SessionPeer::check_and_update_continuous_segment(
                &mut Some(&mut left),
                &mut None,
                &mut seg
            ),
            ContinuousFlags::DISCONTINUOUS
        );

        // {31, 10}, {51, 5}
        let mut seg = SeqSegment { seq: 41, len: 10 };
        let mut left = SeqSegment { seq: 31, len: 10 };
        let mut right = SeqSegment { seq: 51, len: 5 };
        assert_ne!(
            SessionPeer::check_and_update_continuous_segment(
                &mut Some(&mut left),
                &mut Some(&mut right),
                &mut seg
            ),
            ContinuousFlags::DISCONTINUOUS
        );
    }

    #[test]
    fn merge_seq_list() {
        fn helper(p: &mut SessionPeer, seg: SeqSegment, position: isize) {
            if position < 0 {
                p.insert_seq_segment(0, seg);
                p.merge_seq_list(0);
            } else if position == 0 {
                p.insert_seq_segment(p.seq_list_len as usize / 2, seg);
                p.merge_seq_list(p.seq_list_len as usize / 2);
            } else {
                p.insert_seq_segment(p.seq_list_len as usize, seg);
                p.merge_seq_list(p.seq_list_len as usize - 2);
            }
        }

        let mut peer = SessionPeer::default();

        let mut expected: [SeqSegment; SEQ_LIST_MAX_LEN] = Default::default();
        for i in 1..=SEQ_LIST_MAX_LEN {
            let header = MetaPacketTcpHeader {
                seq: i as u32 * 100,
                ack: 20,
                ..Default::default()
            };
            peer.assert_seq_number(&header, 10);
            if i != SEQ_LIST_MAX_LEN {
                expected[i - 1] = SeqSegment {
                    seq: (SEQ_LIST_MAX_LEN + 1 - i) as u32 * 100,
                    len: 10,
                };
            }
        }
        expected[SEQ_LIST_MAX_LEN - 2] = SeqSegment { seq: 100, len: 110 };
        assert_eq!(peer.seq_list_len, 15);
        assert_eq!(peer.seq_list, expected);

        helper(
            &mut peer,
            SeqSegment {
                seq: (SEQ_LIST_MAX_LEN * 100 + 10) as u32,
                len: 10,
            },
            -1,
        );
        expected[0] = SeqSegment { seq: 1600, len: 20 };
        assert_eq!(peer.seq_list, expected);

        helper(&mut peer, SeqSegment { seq: 320, len: 10 }, 0);
        expected[7] = SeqSegment { seq: 320, len: 10 };
        expected[8] = SeqSegment { seq: 800, len: 110 };
        assert_eq!(peer.seq_list, expected);

        helper(&mut peer, SeqSegment { seq: 10, len: 10 }, 1);
        expected[SEQ_LIST_MAX_LEN - 2] = SeqSegment { seq: 10, len: 200 };
        assert_eq!(peer.seq_list, expected);
    }

    #[test]
    fn session_peer_seq_no_assert() {
        let mut peer = SessionPeer::default();

        assert_eq!(
            peer.assert_seq_number(&MetaPacketTcpHeader::default(), 0),
            PacketSeqType::NotCare
        );
        assert_eq!(
            peer.assert_seq_number(&MetaPacketTcpHeader::default(), 1),
            PacketSeqType::NotCare
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 10,
                    ack: 20,
                    ..Default::default()
                },
                10
            ),
            PacketSeqType::NotCare
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 20,
                    ..Default::default()
                },
                10
            ),
            PacketSeqType::Continuous
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 10,
                    ..Default::default()
                },
                10
            ),
            PacketSeqType::Retrans
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 20,
                    ..Default::default()
                },
                10
            ),
            PacketSeqType::Retrans
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 40,
                    ..Default::default()
                },
                20
            ),
            PacketSeqType::Discontinuous
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 10,
                    ..Default::default()
                },
                21
            ),
            PacketSeqType::Error
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 29,
                    ..Default::default()
                },
                5
            ),
            PacketSeqType::Error
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 10,
                    ..Default::default()
                },
                20
            ),
            PacketSeqType::Retrans
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 31,
                    ..Default::default()
                },
                4
            ),
            PacketSeqType::Discontinuous
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 30,
                    ..Default::default()
                },
                1
            ),
            PacketSeqType::BothContinuous
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 35,
                    ..Default::default()
                },
                2
            ),
            PacketSeqType::Continuous
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 39,
                    ..Default::default()
                },
                1
            ),
            PacketSeqType::Continuous
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 38,
                    ..Default::default()
                },
                7
            ),
            PacketSeqType::Error
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 10,
                    ..Default::default()
                },
                28
            ),
            PacketSeqType::Error
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 35,
                    ..Default::default()
                },
                5
            ),
            PacketSeqType::Error
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 5,
                    ..Default::default()
                },
                5
            ),
            PacketSeqType::Continuous
        );
        assert_eq!(
            peer.assert_seq_number(
                &MetaPacketTcpHeader {
                    seq: 1,
                    ..Default::default()
                },
                3
            ),
            PacketSeqType::Discontinuous
        );

        assert_eq!(
            <&[SeqSegment; 3]>::try_from(&peer.seq_list[..peer.seq_list_len as usize]).unwrap(),
            &[
                SeqSegment { seq: 39, len: 21 },
                SeqSegment { seq: 5, len: 32 },
                SeqSegment { seq: 1, len: 3 }
            ]
        );
    }

    // TODO: fix this test that checks nothing
    #[test]
    fn reestablish_fsm() {
        let mut perf = TcpPerf::new(Arc::new(FlowPerfCounter::default()));

        // 1SYN -> 2SYN/ACK -> 1ACK -> 1ACK/LEN>0 -> 2ACK -> 2ACK/LEN>0 -> 1ACK -> 1ACK/LEN>0
        // 1SYN
        let packet = MiniMetaPacket {
            flags: TcpFlags::SYN,
            seq: 111,
            ack: 0,
            timestamp: 3333,
            ..Default::default()
        }
        .into();
        perf.parse(&packet, true).unwrap();
        perf.ctrl_info.0.update_data(&packet);

        // 2SYN/ACK rttSum1 = 1
        let packet = MiniMetaPacket {
            flags: TcpFlags::SYN_ACK,
            seq: 1111,
            ack: 112,
            timestamp: 3334,
            ..Default::default()
        }
        .into();
        perf.parse(&packet, false).unwrap();
        perf.ctrl_info.1.update_data(&packet);

        // 1ACK rttSum0 = 10
        let packet = MiniMetaPacket {
            flags: TcpFlags::ACK,
            seq: 112,
            ack: 1112,
            timestamp: 3344,
            ..Default::default()
        }
        .into();
        perf.parse(&packet, true).unwrap();
        perf.ctrl_info.0.update_data(&packet);

        // 1ACK/LEN>0 len=100
        let packet = MiniMetaPacket {
            flags: TcpFlags::ACK,
            seq: 112,
            ack: 1112,
            timestamp: 3350,
            payload_len: 100,
            packet_len: 100,
            ..Default::default()
        }
        .into();
        perf.parse(&packet, true).unwrap();
        perf.ctrl_info.0.update_data(&packet);

        // 2ACK srt1 = 4
        let packet = MiniMetaPacket {
            flags: TcpFlags::ACK,
            seq: 1112,
            ack: 212,
            timestamp: 3354,
            ..Default::default()
        }
        .into();
        perf.parse(&packet, false).unwrap();
        perf.ctrl_info.1.update_data(&packet);

        // 2ACK/LEN>0 len=500 art1 = 30
        let packet = MiniMetaPacket {
            flags: TcpFlags::PSH_ACK,
            seq: 1112,
            ack: 212,
            packet_len: 500,
            payload_len: 500,
            timestamp: 3384,
            ..Default::default()
        }
        .into();
        perf.parse(&packet, false).unwrap();
        perf.ctrl_info.1.update_data(&packet);

        // 1ACK srt0 = 16
        let packet = MiniMetaPacket {
            flags: TcpFlags::ACK,
            seq: 212,
            ack: 1612,
            timestamp: 3400,
            ..Default::default()
        }
        .into();
        perf.parse(&packet, true).unwrap();
        perf.ctrl_info.0.update_data(&packet);

        // 1ACK/LEN>0 len=200 art0 = 54
        let packet = MiniMetaPacket {
            flags: TcpFlags::ACK,
            seq: 212,
            ack: 1612,
            timestamp: 3454,
            packet_len: 200,
            payload_len: 200,
            ..Default::default()
        }
        .into();
        perf.parse(&packet, true).unwrap();
        perf.ctrl_info.0.update_data(&packet);
    }

    #[test]
    fn preprocess() {
        let perf = TcpPerf::new(Arc::new(FlowPerfCounter::default()));

        let packet = MiniMetaPacket {
            data_offset: 5,
            flags: TcpFlags::SYN | TcpFlags::ACK | TcpFlags::PSH | TcpFlags::URG,
            timestamp: 1000,
            ..Default::default()
        }
        .into();
        assert!(perf.is_interested_packet(&packet));

        let packet = MiniMetaPacket {
            data_offset: 5,
            flags: TcpFlags::ACK | TcpFlags::PSH | TcpFlags::URG,
            ..Default::default()
        }
        .into();
        assert!(perf.is_interested_packet(&packet));

        let packet = MiniMetaPacket {
            data_offset: 5,
            flags: TcpFlags::RST,
            ..Default::default()
        }
        .into();
        assert!(!perf.is_interested_packet(&packet));

        let packet = MiniMetaPacket {
            data_offset: 5,
            flags: TcpFlags::FIN,
            ..Default::default()
        }
        .into();
        assert!(!perf.is_interested_packet(&packet));
    }

    // TODO: fix this broken test (also fails in go code)
    #[test]
    #[should_panic]
    fn meta_flow_perf_update() {
        let mut perf = TcpPerf::new(Arc::new(FlowPerfCounter::default()));
        _meta_flow_perf_update(&mut perf);

        let perf_data = PerfData {
            rtt_0: TimeStats {
                sum: Timestamp::from_nanos(10),
                max: Timestamp::from_nanos(2),
                updated: true,
                ..Default::default()
            },
            rtt_1: TimeStats {
                sum: Timestamp::from_nanos(1),
                max: Timestamp::from_nanos(1),
                updated: true,
                ..Default::default()
            },
            art_0: TimeStats {
                sum: Timestamp::from_nanos(70),
                max: Timestamp::from_nanos(70),
                count: 1,
                updated: true,
                ..Default::default()
            },
            srt_0: TimeStats {
                sum: Timestamp::from_nanos(16),
                max: Timestamp::from_nanos(16),
                count: 2,
                updated: true,
                ..Default::default()
            },
            srt_1: TimeStats {
                count: 1,
                updated: true,
                ..Default::default()
            },
            zero_win_count_0: 3,
            zero_win_count_1: 5,
            updated: true,
            ..Default::default()
        };

        assert_eq!(perf.perf_data, perf_data);
    }

    #[test]
    fn report() {
        let pcap_file = Path::new(FILE_DIR).join("art-continues-payload-len-larger-than-1.pcap");

        let mut output = String::new();
        // flow结束后上报
        output.push_str(&report_test_helper(&pcap_file, -1, false, 0, None));
        output.push('\n');
        // flow结束后反向上报
        output.push_str(&report_test_helper(&pcap_file, -1, true, 0, None));
        output.push('\n');
        // 握手成功后第一次上报
        output.push_str(&report_test_helper(&pcap_file, 3, false, 0, None));
        output.push('\n');
        // 计算出rttSum1(即syn/ack包之后)后第一次上报
        output.push_str(&report_test_helper(&pcap_file, 2, false, 0, None));
        output.push('\n');
        // 丢掉第一个包(syn包)，模拟仅计算出rttSum0后第一次上报
        output.push_str(&report_test_helper(&pcap_file, 3, false, 1, None));
        output.push('\n');
        // 丢掉第三个包(ack包)，模拟仅计算出rttSum1后第一次上报
        output.push_str(&report_test_helper(&pcap_file, 2, false, 3, None));
        output.push('\n');
        // 2次上报rttsum, 2次均完整计算出rttSum0, rttSum1
        output.push_str(&report_test_helper(&pcap_file, -1, false, 0, Some(3)));
        output.push('\n');
        // 2次上报rttsum, 第2次上报仅计算出rttSum1
        output.push_str(&report_test_helper(&pcap_file, -1, false, 3, Some(3)));
        output.push('\n');

        let expected = fs::read_to_string(&Path::new(FILE_DIR).join("report.result")).unwrap();
        if output != expected {
            let output_path = Path::new("actual.txt");
            fs::write(&output_path, &output).unwrap();
            assert!(
                output == expected,
                "output different from expected, written to {:?}",
                output_path
            );
        }
    }

    fn update_test_helper<P: AsRef<Path>>(file: P, check_seq_list: bool) -> String {
        let mut output = String::new();

        let mut perf = TcpPerf::new(Arc::new(FlowPerfCounter::default()));
        let capture = Capture::load_pcap(file, None);
        let packets = capture.as_meta_packets();
        assert!(
            packets.len() >= 2,
            "calculating flow perf requires 2 packets at least"
        );

        let first_packet = &packets[0];
        for (i, packet) in packets.iter().enumerate() {
            let tcp_data = if let ProtocolData::TcpHeader(tcp_data) = &packet.protocol_data {
                tcp_data
            } else {
                unreachable!();
            };
            assert!(
                tcp_data.data_offset > 0,
                "raw packet is not tcp, packet#{} is {}",
                i,
                packet
            );
            let _ = perf.parse(
                packet,
                first_packet.lookup_key.src_ip == packet.lookup_key.src_ip,
            );
            output.push_str(&format!("{}th perf data:\n{:#?}\n", i, perf.perf_data));
            if check_seq_list {
                output.push_str(&format!(
                    "\t\tclient seq_list: {:?}\n",
                    &perf.ctrl_info.0.seq_list[..perf.ctrl_info.0.seq_list_len as usize]
                ));
                output.push_str(&format!(
                    "\t\tserver seq_list: {:?}\n",
                    &perf.ctrl_info.1.seq_list[..perf.ctrl_info.1.seq_list_len as usize]
                ));
            }
        }
        output
    }

    fn perf_test_helper<P: AsRef<Path>, Q: AsRef<Path>>(
        files: &Vec<P>,
        result: Q,
        check_seq_list: bool,
    ) {
        let output = files
            .iter()
            .map(|file| update_test_helper(&Path::new(FILE_DIR).join(file), check_seq_list))
            .collect::<Vec<_>>()
            .join("");
        let expected = fs::read_to_string(&Path::new(FILE_DIR).join(result)).unwrap();
        if output != expected {
            let output_path = Path::new("actual.txt");
            fs::write(&output_path, &output).unwrap();
            assert!(
                output == expected,
                "output different from expected, written to {:?}",
                output_path
            );
        }
    }

    fn report_test_helper<P: AsRef<Path>>(
        file: P,
        first_report_moment: isize,
        reverse_flow: bool,
        ignore_nth_packet: usize,
        reuse_first_n_packets: Option<usize>,
    ) -> String {
        let mut output = String::new();

        let mut perf = TcpPerf::new(Arc::new(FlowPerfCounter::default()));
        let capture = Capture::load_pcap(file, None);
        let mut packets = capture.as_meta_packets();
        assert!(
            packets.len() >= 2,
            "calculating flow perf requires 2 packets at least"
        );

        let first_packet_src_ip = packets[0].lookup_key.src_ip;
        if let Some(n) = reuse_first_n_packets {
            assert!(n < packets.len());
            for i in 0..n {
                let packet = &packets[i];
                let tcp_data = if let ProtocolData::TcpHeader(tcp_data) = &packet.protocol_data {
                    tcp_data
                } else {
                    unreachable!();
                };
                assert!(tcp_data.data_offset != 0);
                perf.parse(&packet, first_packet_src_ip == packet.lookup_key.src_ip)
                    .unwrap();
            }
            let report = perf.copy_and_reset_data(reverse_flow);
            output.push_str(&format!(
                "report after reuse {} packets:\n{:#?}\n",
                n, &report.tcp
            ));
        }

        for (i, packet) in packets.iter_mut().enumerate() {
            packet.lookup_key.timestamp += Timestamp::from_secs(60);
            if i + 1 == ignore_nth_packet {
                continue;
            }
            let tcp_data = if let ProtocolData::TcpHeader(tcp_data) = &packet.protocol_data {
                tcp_data
            } else {
                unreachable!();
            };
            assert!(tcp_data.data_offset != 0);
            let _ = perf.parse(&*packet, first_packet_src_ip == packet.lookup_key.src_ip);

            if first_report_moment == i as isize + 1 {
                let report = perf.copy_and_reset_data(reverse_flow);
                output.push_str(&format!(
                    "report after {}th packet:\n{:#?}\n",
                    first_report_moment, &report.tcp
                ));
            }
        }
        let report = perf.copy_and_reset_data(reverse_flow);
        output.push_str(&format!("report after last packet:\n{:#?}\n", &report.tcp));

        output
    }
}
