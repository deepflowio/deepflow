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

use std::{fmt, path::Path, time::Duration};

use pcap::{self, Linktype};

use crate::common::meta_packet::{MetaPacket, PcapData};

pub struct Capture {
    cap: pcap::Capture<pcap::Offline>,
    dl_type: Linktype,
}

impl Capture {
    pub fn load_pcap<P: AsRef<Path>>(path: P) -> Self {
        let cap = pcap::Capture::from_file(path).unwrap();
        let dl_type = cap.get_datalink();
        Self { cap, dl_type }
    }
}

impl Iterator for Capture {
    type Item = MetaPacket<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        self.cap.next_packet().ok().and_then(|packet| {
            let pcap_data = PcapData {
                link_type: self.dl_type,
                timestamp: Duration::new(
                    packet.header.ts.tv_sec as u64,
                    packet.header.ts.tv_usec as u32 * 1000,
                ),
                data: packet.data,
            };
            MetaPacket::try_from(pcap_data).ok().map(|p| p.into_owned())
        })
    }
}

impl From<Capture> for Vec<Vec<u8>> {
    fn from(mut c: Capture) -> Self {
        let mut vec = Vec::new();
        while let Ok(p) = c.cap.next_packet() {
            vec.push(p.data.to_vec());
        }
        vec
    }
}

pub struct WrappedDebugStruct<'a, 'b: 'a>(fmt::DebugStruct<'a, 'b>);

impl<'a, 'b> From<fmt::DebugStruct<'a, 'b>> for WrappedDebugStruct<'a, 'b> {
    fn from(ds: fmt::DebugStruct<'a, 'b>) -> Self {
        Self(ds)
    }
}

impl<'a, 'b: 'a> WrappedDebugStruct<'a, 'b> {
    pub fn field_skip_default<F>(
        &mut self,
        field: &str,
        value: &F,
    ) -> &mut WrappedDebugStruct<'a, 'b>
    where
        F: fmt::Debug + Default + PartialEq,
    {
        if value != &F::default() {
            self.0.field(field, value);
        }
        self
    }

    pub fn field<F>(&mut self, field: &str, value: &F) -> &mut WrappedDebugStruct<'a, 'b>
    where
        F: fmt::Debug,
    {
        self.0.field(field, value);
        self
    }

    pub fn finish(&mut self) -> fmt::Result {
        self.0.finish()
    }
}
