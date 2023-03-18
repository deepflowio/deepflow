/*
 * Copyright (c) 2022 Yunshan Networks
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
    ptr,
};

use prost::Message;
use public::utils::string::get_string_from_chars;
use public::{
    bytes::{read_u32_le, read_u64_le},
    proto::metric,
    sender::{SendMessageType, Sendable},
};

use crate::common::{
    ebpf::IO_EVENT,
    error::Error::{self, ParseEventData},
};
use crate::ebpf::{PACKET_KNAME_MAX_PADDING, SK_BPF_DATA};

const FILE_NAME_MAX_PADDING: usize = 64;
const IO_BYTES_COUNT_OFFSET: usize = 4;
const IO_OPERATION_OFFSET: usize = 8;
const IO_LATENCY_OFFSET: usize = 16;
struct IoEventData {
    bytes_count: u32,                      // Number of bytes read and written
    operation: u32,                        // 0: write 1: read
    latency: u64,                          // Function call delay, in nanoseconds
    filename: [u8; FILE_NAME_MAX_PADDING], // String ending with \0
}

impl TryFrom<&[u8]> for IoEventData {
    type Error = Error;

    fn try_from(raw_data: &[u8]) -> Result<Self, self::Error> {
        let length = raw_data.len();
        if length <= FILE_NAME_MAX_PADDING {
            return Err(ParseEventData(format!(
                "parse io event data failed, raw data length: {} < {}",
                length, FILE_NAME_MAX_PADDING
            )));
        }
        let mut io_event_data = Self {
            bytes_count: read_u32_le(&raw_data),
            operation: read_u32_le(&raw_data[IO_BYTES_COUNT_OFFSET..]),
            latency: read_u64_le(&raw_data[IO_OPERATION_OFFSET..]),
            filename: [0u8; FILE_NAME_MAX_PADDING],
        };
        io_event_data
            .filename
            .copy_from_slice(&raw_data[IO_LATENCY_OFFSET..]);
        Ok(io_event_data)
    }
}

impl From<IoEventData> for metric::IoEventData {
    fn from(io_event_data: IoEventData) -> Self {
        Self {
            bytes_count: io_event_data.bytes_count,
            operation: io_event_data.operation as i32,
            latency: io_event_data.latency,
            filename: io_event_data.filename.to_vec(),
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
            EventData::IoEvent(d) => {
                let filename = get_string_from_chars(&d.filename);
                f.write_fmt(format_args!(
                    "IoEventData {{ filename: {:?}, operation: {}, bytes_count: {}, latency: {} }}",
                    filename, d.operation, d.bytes_count, d.latency
                ))
            }
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
    pid: u32,
    thread_id: u32,
    coroutine_id: u64, // optional
    process_kname: [u8; PACKET_KNAME_MAX_PADDING + 1],
    start_time: u64, // unit: μs
    end_time: u64,   // unit: μs
    event_type: EventType,
    event_data: EventData,
}

impl ProcEvent {
    pub unsafe fn from_ebpf(
        data: *mut SK_BPF_DATA,
        event_type: EventType,
    ) -> Result<BoxedProcEvents, Error> {
        let data = &mut (*data);
        let cap_len = data.cap_len as usize;
        let mut raw_data = vec![0u8; cap_len as usize]; // Copy from data.cap_data where stores event's data
        #[cfg(target_arch = "aarch64")]
        data.cap_data
            .copy_to_nonoverlapping(raw_data.as_mut_ptr() as *mut u8, cap_len);
        #[cfg(target_arch = "x86_64")]
        data.cap_data
            .copy_to_nonoverlapping(raw_data.as_mut_ptr() as *mut i8, cap_len);

        let mut event_data: EventData = EventData::OtherEvent;
        let mut end_time = 0;
        match event_type {
            EventType::IoEvent => {
                let io_event_data = IoEventData::try_from(raw_data.as_ref())?; // Try to parse IoEventData from data.cap_data
                end_time = data.timestamp + io_event_data.latency / 1000; // The unit of timestamp is microsecond, and the unit of latency is nanosecond
                event_data = EventData::IoEvent(io_event_data);
            }
            _ => {}
        }

        let mut proc_event = ProcEvent {
            pid: data.process_id,
            thread_id: data.thread_id,
            coroutine_id: data.coroutine_id,
            process_kname: [0u8; PACKET_KNAME_MAX_PADDING + 1],
            start_time: data.timestamp,
            end_time,
            event_type,
            event_data,
        };

        #[cfg(target_arch = "aarch64")]
        ptr::copy(
            data.process_kname.as_ptr() as *const u8,
            proc_event.process_kname.as_mut_ptr() as *mut u8,
            PACKET_KNAME_MAX_PADDING,
        );
        #[cfg(target_arch = "x86_64")]
        ptr::copy(
            data.process_kname.as_ptr() as *const i8,
            proc_event.process_kname.as_mut_ptr() as *mut i8,
            PACKET_KNAME_MAX_PADDING,
        );
        Ok(BoxedProcEvents(Box::new(proc_event)))
    }
}

#[derive(Debug)]
pub struct BoxedProcEvents(pub Box<ProcEvent>);

impl Debug for ProcEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "ProcEvent {{ pid: {}, thread_id: {}, coroutine_id: {}, process_kname: {}, event_type: {}, start_time: {}, end_time: {}, event_data: {:?} }}",
            self.pid, self.thread_id, self.coroutine_id, get_string_from_chars(&self.process_kname), self.event_type, self.start_time, self.end_time, self.event_data
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
            process_kname: self.0.process_kname.to_vec(),
            end_time: self.0.end_time,
            event_type: self.0.event_type.into(),
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
