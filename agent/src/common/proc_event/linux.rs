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

use std::{
    fmt::{self, Debug, Formatter},
    slice, str,
};

use prost::Message;
use public::{
    bytes::{read_u16_le, read_u32_le, read_u64_le},
    proto::metric,
    sender::{SendMessageType, Sendable},
};

use crate::common::{
    ebpf::{FILE_OP_EVENT, IO_EVENT, PERM_OP_EVENT, PROC_LIFECYCLE_EVENT},
    error::Error::{self, ParseEventData},
};
use crate::ebpf::SK_BPF_DATA;

// ── IoEventData offsets (matches user_io_event_buffer) ──────────────────
const IO_OPERATION_OFFSET: usize = 4;
const IO_LATENCY_OFFSET: usize = 8;
const IO_OFF_BYTES_OFFSET: usize = 16;
const IO_FILE_TYPE_OFFSET: usize = 24;
const IO_FILE_NAME_OFFSET: usize = 28;
const IO_MOUNT_SOURCE_OFFSET: usize = 284;
const IO_MOUNT_POINT_OFFSET: usize = 796;
const IO_FILE_DIR_OFFSET: usize = 1052;
const IO_MNT_ID_OFFSET: usize = 1564;
const IO_MNTNS_ID_OFFSET: usize = 1568;
const IO_ACCESS_PERMISSION_OFFSET: usize = 1572;
const IO_EVENT_BUFF_SIZE: usize = 1574;

struct IoEventData {
    bytes_count: u32, // Number of bytes read and written
    operation: u32,   // 0: write 1: read
    latency: u64,     // Function call delay, in nanoseconds
    off_bytes: u64,   // The number of bytes of offset within the file content
    file_type: u32,   // File type: 0: unknown, 1: regular, 2: virtual, 3: network
    filename: Vec<u8>,
    mount_source: Vec<u8>,
    mount_point: Vec<u8>,
    file_dir: Vec<u8>,
    access_permission: u16, // File permission bits (inode->i_mode & 0xFFF)
}

impl TryFrom<&[u8]> for IoEventData {
    type Error = Error;

    fn try_from(raw_data: &[u8]) -> Result<Self, self::Error> {
        fn parse_cstring_slice(slice: &[u8]) -> Vec<u8> {
            match slice.iter().position(|&b| b == b'\0') {
                Some(index) => slice[..index].to_vec(),
                None => vec![],
            }
        }
        let length = raw_data.len();
        if length < IO_EVENT_BUFF_SIZE {
            return Err(ParseEventData(format!(
                "parse io event data failed, raw data length: {length} < {IO_EVENT_BUFF_SIZE}"
            )));
        }
        let io_event_data = Self {
            bytes_count: read_u32_le(&raw_data),
            operation: read_u32_le(&raw_data[IO_OPERATION_OFFSET..]),
            latency: read_u64_le(&raw_data[IO_LATENCY_OFFSET..]),
            off_bytes: read_u64_le(&raw_data[IO_OFF_BYTES_OFFSET..]),
            file_type: read_u32_le(&raw_data[IO_FILE_TYPE_OFFSET..]),
            filename: parse_cstring_slice(&raw_data[IO_FILE_NAME_OFFSET..]),
            mount_source: parse_cstring_slice(&raw_data[IO_MOUNT_SOURCE_OFFSET..]),
            mount_point: parse_cstring_slice(&raw_data[IO_MOUNT_POINT_OFFSET..]),
            file_dir: parse_cstring_slice(&raw_data[IO_FILE_DIR_OFFSET..]),
            access_permission: read_u16_le(&raw_data[IO_ACCESS_PERMISSION_OFFSET..]),
        };
        Ok(io_event_data)
    }
}

impl From<IoEventData> for metric::IoEventData {
    fn from(io_event_data: IoEventData) -> Self {
        Self {
            bytes_count: io_event_data.bytes_count,
            operation: io_event_data.operation as i32,
            latency: io_event_data.latency,
            off_bytes: io_event_data.off_bytes,
            filename: io_event_data.filename,
            mount_source: io_event_data.mount_source,
            mount_point: io_event_data.mount_point,
            file_dir: io_event_data.file_dir,
            file_type: io_event_data.file_type as i32,
            access_permission: io_event_data.access_permission as u32,
        }
    }
}

// ── FileOpEventData offsets (packed __ai_agent_file_op_event) ───────────
// Layout: event_type(1) + pid(4) + uid(4) + gid(4) + mode(4) + timestamp(8) + filename(256)
const FILE_OP_MIN_SIZE: usize = 25; // without filename
const FILE_OP_PID_OFF: usize = 1;
const FILE_OP_UID_OFF: usize = 5;
const FILE_OP_GID_OFF: usize = 9;
const FILE_OP_MODE_OFF: usize = 13;
const FILE_OP_TS_OFF: usize = 17;
const FILE_OP_FNAME_OFF: usize = 25;

struct FileOpEventData {
    op_type: u8,
    pid: u32,
    uid: u32,
    gid: u32,
    mode: u32,
    timestamp: u64,
    filename: Vec<u8>,
}

impl TryFrom<&[u8]> for FileOpEventData {
    type Error = Error;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < FILE_OP_MIN_SIZE {
            return Err(ParseEventData(format!(
                "file_op event too short: {} < {FILE_OP_MIN_SIZE}",
                raw.len()
            )));
        }
        let filename = if raw.len() > FILE_OP_FNAME_OFF {
            let slice = &raw[FILE_OP_FNAME_OFF..];
            match slice.iter().position(|&b| b == b'\0') {
                Some(i) => slice[..i].to_vec(),
                None => slice.to_vec(),
            }
        } else {
            vec![]
        };
        Ok(Self {
            op_type: raw[0],
            pid: read_u32_le(&raw[FILE_OP_PID_OFF..]),
            uid: read_u32_le(&raw[FILE_OP_UID_OFF..]),
            gid: read_u32_le(&raw[FILE_OP_GID_OFF..]),
            mode: read_u32_le(&raw[FILE_OP_MODE_OFF..]),
            timestamp: read_u64_le(&raw[FILE_OP_TS_OFF..]),
            filename,
        })
    }
}

impl From<FileOpEventData> for metric::FileOpEventData {
    fn from(d: FileOpEventData) -> Self {
        Self {
            op_type: d.op_type as i32,
            pid: d.pid,
            uid: d.uid,
            gid: d.gid,
            mode: d.mode,
            timestamp: d.timestamp,
            filename: d.filename,
        }
    }
}

// ── PermOpEventData offsets (packed __ai_agent_perm_event) ──────────────
// Layout: event_type(1) + pid(4) + old_uid(4) + old_gid(4) + new_uid(4) + new_gid(4) + timestamp(8)
const PERM_OP_SIZE: usize = 29;
const PERM_OP_PID_OFF: usize = 1;
const PERM_OP_OLD_UID_OFF: usize = 5;
const PERM_OP_OLD_GID_OFF: usize = 9;
const PERM_OP_NEW_UID_OFF: usize = 13;
const PERM_OP_NEW_GID_OFF: usize = 17;
const PERM_OP_TS_OFF: usize = 21;

struct PermOpEventData {
    op_type: u8,
    pid: u32,
    old_uid: u32,
    old_gid: u32,
    new_uid: u32,
    new_gid: u32,
    timestamp: u64,
}

impl TryFrom<&[u8]> for PermOpEventData {
    type Error = Error;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < PERM_OP_SIZE {
            return Err(ParseEventData(format!(
                "perm_op event too short: {} < {PERM_OP_SIZE}",
                raw.len()
            )));
        }
        Ok(Self {
            op_type: raw[0],
            pid: read_u32_le(&raw[PERM_OP_PID_OFF..]),
            old_uid: read_u32_le(&raw[PERM_OP_OLD_UID_OFF..]),
            old_gid: read_u32_le(&raw[PERM_OP_OLD_GID_OFF..]),
            new_uid: read_u32_le(&raw[PERM_OP_NEW_UID_OFF..]),
            new_gid: read_u32_le(&raw[PERM_OP_NEW_GID_OFF..]),
            timestamp: read_u64_le(&raw[PERM_OP_TS_OFF..]),
        })
    }
}

impl From<PermOpEventData> for metric::PermOpEventData {
    fn from(d: PermOpEventData) -> Self {
        Self {
            op_type: d.op_type as i32,
            pid: d.pid,
            old_uid: d.old_uid,
            old_gid: d.old_gid,
            new_uid: d.new_uid,
            new_gid: d.new_gid,
            timestamp: d.timestamp,
        }
    }
}

// ── ProcLifecycleEventData offsets (packed __ai_agent_proc_event) ───────
// Layout: event_type(1) + pid(4) + parent_pid(4) + uid(4) + gid(4) + timestamp(8) + comm(16)
const PROC_LIFECYCLE_MIN_SIZE: usize = 25; // without comm
const PROC_LC_PID_OFF: usize = 1;
const PROC_LC_PPID_OFF: usize = 5;
const PROC_LC_UID_OFF: usize = 9;
const PROC_LC_GID_OFF: usize = 13;
const PROC_LC_TS_OFF: usize = 17;
const PROC_LC_COMM_OFF: usize = 25;
pub const PROC_LIFECYCLE_FORK: u8 = 1;
pub const PROC_LIFECYCLE_EXEC: u8 = 2;
pub const PROC_LIFECYCLE_EXIT: u8 = 3;

struct ProcLifecycleEventData {
    lifecycle_type: u8,
    pid: u32,
    parent_pid: u32,
    uid: u32,
    gid: u32,
    timestamp: u64,
    comm: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcLifecycleInfo {
    pub lifecycle_type: u8,
    pub pid: u32,
    pub parent_pid: u32,
}

impl TryFrom<&[u8]> for ProcLifecycleEventData {
    type Error = Error;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < PROC_LIFECYCLE_MIN_SIZE {
            return Err(ParseEventData(format!(
                "proc_lifecycle event too short: {} < {PROC_LIFECYCLE_MIN_SIZE}",
                raw.len()
            )));
        }
        let comm = if raw.len() > PROC_LC_COMM_OFF {
            let slice = &raw[PROC_LC_COMM_OFF..];
            match slice.iter().position(|&b| b == b'\0') {
                Some(i) => slice[..i].to_vec(),
                None => slice.to_vec(),
            }
        } else {
            vec![]
        };
        Ok(Self {
            lifecycle_type: raw[0],
            pid: read_u32_le(&raw[PROC_LC_PID_OFF..]),
            parent_pid: read_u32_le(&raw[PROC_LC_PPID_OFF..]),
            uid: read_u32_le(&raw[PROC_LC_UID_OFF..]),
            gid: read_u32_le(&raw[PROC_LC_GID_OFF..]),
            timestamp: read_u64_le(&raw[PROC_LC_TS_OFF..]),
            comm,
        })
    }
}

impl From<ProcLifecycleEventData> for metric::ProcLifecycleEventData {
    fn from(d: ProcLifecycleEventData) -> Self {
        Self {
            lifecycle_type: d.lifecycle_type as i32,
            pid: d.pid,
            parent_pid: d.parent_pid,
            uid: d.uid,
            gid: d.gid,
            timestamp: d.timestamp,
            comm: d.comm,
        }
    }
}

// ── EventData ──────────────────────────────────────────────────────────
enum EventData {
    OtherEvent,
    IoEvent(IoEventData),
    FileOpEvent(FileOpEventData),
    PermOpEvent(PermOpEventData),
    ProcLifecycleEvent(ProcLifecycleEventData),
}

impl Debug for EventData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            EventData::IoEvent(d) => f.write_fmt(format_args!(
                "IoEventData {{ filename: {}, operation: {}, bytes_count: {}, latency: {}, off_bytes: {} }}",
                str::from_utf8(&d.filename).unwrap_or(""),
                d.operation,
                d.bytes_count,
                d.latency,
                d.off_bytes
            )),
            EventData::FileOpEvent(d) => f.write_fmt(format_args!(
                "FileOpEventData {{ op_type: {}, pid: {}, filename: {} }}",
                d.op_type,
                d.pid,
                str::from_utf8(&d.filename).unwrap_or("")
            )),
            EventData::PermOpEvent(d) => f.write_fmt(format_args!(
                "PermOpEventData {{ op_type: {}, pid: {}, new_uid: {}, new_gid: {} }}",
                d.op_type, d.pid, d.new_uid, d.new_gid
            )),
            EventData::ProcLifecycleEvent(d) => f.write_fmt(format_args!(
                "ProcLifecycleEventData {{ type: {}, pid: {}, parent_pid: {} }}",
                d.lifecycle_type, d.pid, d.parent_pid
            )),
            _ => f.write_str("other event"),
        }
    }
}

// ── EventType ──────────────────────────────────────────────────────────
#[derive(PartialEq)]
pub enum EventType {
    OtherEvent = 0,
    IoEvent = 1,
    FileOpEvent = 2,
    PermOpEvent = 3,
    ProcLifecycleEvent = 4,
}

impl From<u8> for EventType {
    fn from(source: u8) -> Self {
        match source {
            IO_EVENT => Self::IoEvent,
            FILE_OP_EVENT => Self::FileOpEvent,
            PERM_OP_EVENT => Self::PermOpEvent,
            PROC_LIFECYCLE_EVENT => Self::ProcLifecycleEvent,
            _ => Self::OtherEvent,
        }
    }
}

impl From<EventType> for i32 {
    fn from(event_type: EventType) -> Self {
        event_type as i32
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherEvent => write!(f, "other_event"),
            Self::IoEvent => write!(f, "io_event"),
            Self::FileOpEvent => write!(f, "file_op_event"),
            Self::PermOpEvent => write!(f, "perm_op_event"),
            Self::ProcLifecycleEvent => write!(f, "proc_lifecycle_event"),
        }
    }
}

// ── ProcEvent ──────────────────────────────────────────────────────────
pub struct ProcEvent {
    pub pid: u32,
    pub pod_id: u32,
    thread_id: u32,
    coroutine_id: u64, // optional
    process_kname: Vec<u8>,
    start_time: u64, // unit: ns
    end_time: u64,   // unit: ns
    event_type: EventType,
    event_data: EventData,
}

impl ProcEvent {
    pub unsafe fn from_ebpf(
        data: &mut SK_BPF_DATA,
        event_type: EventType,
    ) -> Result<BoxedProcEvents, Error> {
        let raw_data = slice::from_raw_parts(data.cap_data as *const u8, data.cap_len as usize);

        let mut event_data: EventData = EventData::OtherEvent;
        let start_time = data.timestamp; // The unit of start_time is nanosecond
        let mut end_time = 0;
        match event_type {
            EventType::IoEvent => {
                let io_event_data = IoEventData::try_from(raw_data)?;
                end_time = start_time + io_event_data.latency;
                event_data = EventData::IoEvent(io_event_data);
            }
            EventType::FileOpEvent => {
                let d = FileOpEventData::try_from(raw_data)?;
                end_time = start_time;
                event_data = EventData::FileOpEvent(d);
            }
            EventType::PermOpEvent => {
                let d = PermOpEventData::try_from(raw_data)?;
                end_time = start_time;
                event_data = EventData::PermOpEvent(d);
            }
            EventType::ProcLifecycleEvent => {
                let d = ProcLifecycleEventData::try_from(raw_data)?;
                end_time = start_time;
                event_data = EventData::ProcLifecycleEvent(d);
            }
            _ => {}
        }

        let proc_event = ProcEvent {
            pid: data.process_id,
            thread_id: data.thread_id,
            coroutine_id: data.coroutine_id,
            process_kname: data
                .process_kname
                .iter()
                .position(|&b| b == b'\0') // data.process_kname ending with '\0'
                .map(|index| &data.process_kname[..index])
                .unwrap_or(&[])
                .to_vec(),
            start_time,
            end_time,
            event_type,
            event_data,
            pod_id: 0,
        };

        Ok(BoxedProcEvents(Box::new(proc_event)))
    }

    pub fn start_time(&self) -> u64 {
        self.start_time
    }

    pub fn proc_lifecycle_info(&self) -> Option<ProcLifecycleInfo> {
        match &self.event_data {
            EventData::ProcLifecycleEvent(data) => Some(ProcLifecycleInfo {
                lifecycle_type: data.lifecycle_type,
                pid: data.pid,
                parent_pid: data.parent_pid,
            }),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct BoxedProcEvents(pub Box<ProcEvent>);

impl Debug for ProcEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "ProcEvent {{ pid: {}, thread_id: {}, coroutine_id: {}, process_kname: {}, event_type: {}, start_time: {}, end_time: {}, event_data: {:?} }}",
            self.pid, self.thread_id, self.coroutine_id, str::from_utf8(&self.process_kname).unwrap_or(""), self.event_type, self.start_time, self.end_time, self.event_data
        ))
    }
}

impl Sendable for BoxedProcEvents {
    fn encode(self, buf: &mut Vec<u8>) -> Result<usize, prost::EncodeError> {
        let mut pb_proc_event: metric::ProcEvent = metric::ProcEvent {
            pid: self.0.pid,
            thread_id: self.0.thread_id,
            coroutine_id: self.0.coroutine_id as u32,
            start_time: self.0.start_time,
            process_kname: self.0.process_kname,
            end_time: self.0.end_time,
            event_type: self.0.event_type.into(),
            pod_id: self.0.pod_id,
            ..Default::default()
        };
        match self.0.event_data {
            EventData::IoEvent(d) => {
                pb_proc_event.io_event_data = Some(d.into());
            }
            EventData::FileOpEvent(d) => {
                pb_proc_event.file_op_event_data = Some(d.into());
            }
            EventData::PermOpEvent(d) => {
                pb_proc_event.perm_op_event_data = Some(d.into());
            }
            EventData::ProcLifecycleEvent(d) => {
                pb_proc_event.proc_lifecycle_event_data = Some(d.into());
            }
            _ => {}
        }
        pb_proc_event
            .encode(buf)
            .map(|_| pb_proc_event.encoded_len())
    }

    fn message_type(&self) -> SendMessageType {
        SendMessageType::ProcEvents
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_lifecycle_info_extracts_fields() {
        let event_data = ProcLifecycleEventData {
            lifecycle_type: 1,
            pid: 4321,
            parent_pid: 1234,
            uid: 0,
            gid: 0,
            timestamp: 42,
            comm: b"sleep".to_vec(),
        };
        let proc_event = ProcEvent {
            pid: 1234,
            pod_id: 0,
            thread_id: 0,
            coroutine_id: 0,
            process_kname: b"python3".to_vec(),
            start_time: 42,
            end_time: 43,
            event_type: EventType::ProcLifecycleEvent,
            event_data: EventData::ProcLifecycleEvent(event_data),
        };

        let info = proc_event.proc_lifecycle_info().expect("missing info");
        assert_eq!(info.lifecycle_type, 1);
        assert_eq!(info.pid, 4321);
        assert_eq!(info.parent_pid, 1234);
    }
}
