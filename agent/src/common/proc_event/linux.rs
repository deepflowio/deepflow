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
    bytes::{read_u32_le, read_u64_le},
    proto::metric,
    sender::{SendMessageType, Sendable},
};

use crate::common::{
    ebpf::IO_EVENT,
    error::Error::{self, ParseEventData},
};
use crate::ebpf::SK_BPF_DATA;

const IO_OPERATION_OFFSET: usize = 4;
const IO_LATENCY_OFFSET: usize = 8;
const IO_OFF_BYTES_OFFSET: usize = 16;
const IO_FILE_TYPE_OFFSET: usize = 24;
const IO_FILE_NAME_OFFSET: usize = 28;
const IO_MOUNT_SOURCE_OFFSET: usize = 284;
const IO_MOUNT_POINT_OFFSET: usize = 796;
const IO_FILE_DIR_OFFSET: usize = 1052;
const IO_EVENT_BUFF_SIZE: usize = 1564;
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
                "parse io event data failed, raw data length: {length} < {IO_OFF_BYTES_OFFSET}"
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
        }
    }
}

enum EventData {
    OtherEvent,
    IoEvent(IoEventData),
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
            _ => f.write_str("other event"),
        }
    }
}

#[derive(PartialEq)]
pub enum EventType {
    OtherEvent = 0,
    IoEvent = 1,
}

impl From<u8> for EventType {
    fn from(source: u8) -> Self {
        match source {
            IO_EVENT => Self::IoEvent,
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
        }
    }
}

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
        let start_time = data.timestamp * 1000; // The unit of data.timestamp is microsecond, and the unit of start_time is nanosecond
        let mut end_time = 0;
        match event_type {
            EventType::IoEvent => {
                let io_event_data = IoEventData::try_from(raw_data)?; // Try to parse IoEventData from data.cap_data
                end_time = start_time + io_event_data.latency;
                event_data = EventData::IoEvent(io_event_data);
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
            EventData::IoEvent(io_event_data) => {
                pb_proc_event.io_event_data = Some(io_event_data.into())
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
