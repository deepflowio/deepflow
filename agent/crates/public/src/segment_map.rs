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

use std::fmt::{Debug, Display};

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Segment<T> {
    pub start: u16,
    pub end: u16,
    pub value: Vec<T>,
}

impl<T: Clone + Copy + Debug> Segment<T> {
    pub fn new(start: u16, end: u16, value: Vec<T>) -> Self {
        assert!(start <= end, "start port must be <= end port");
        Self { start, end, value }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SegmentMap<T> {
    segments: Vec<Segment<T>>,
}

impl<T: Clone + Copy + Debug> SegmentMap<T> {
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    pub fn add_single(&mut self, port: u16, value: Vec<T>) {
        self.add_range(port, port, value);
    }

    pub fn add_range(&mut self, start: u16, end: u16, value: Vec<T>) {
        self.segments.push(Segment::new(start, end, value));
    }

    pub fn merge_segments(&mut self) {
        // events: (port, is_start_port, segment_index)
        let mut events = Vec::new();
        for (idx, segment) in self.segments.iter().enumerate() {
            events.push((segment.start, true, idx));
            if segment.end < u16::MAX {
                events.push((segment.end + 1, false, idx));
            } else {
                events.push((u16::MAX, false, idx));
            }
        }

        events.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));

        let curr_len = self.segments.len();
        let mut resort_segments = Vec::with_capacity(curr_len);
        let mut active_segments = vec![false; curr_len];
        let mut last_pos = 0u16;

        for (pos, is_start, seg_idx) in events {
            if pos > last_pos {
                // 所有活跃的 events 对应的 value 合集，即为新段的 value
                // all active events value concat as new value for new segments
                let all_start_segments_value: Vec<T> = active_segments
                    .iter()
                    .enumerate()
                    .filter(|&(_, &exists)| exists)
                    .flat_map(|(idx, _)| self.segments[idx].value.iter())
                    .copied()
                    .collect();
                if !all_start_segments_value.is_empty() {
                    resort_segments.push(Segment {
                        start: last_pos,
                        end: pos - 1,
                        value: all_start_segments_value,
                    });
                }
            }

            // when meet end port, the segment is no longer active
            active_segments[seg_idx] = is_start;
            last_pos = pos;
        }
        self.segments = resort_segments;
    }

    pub fn find(&self, port: u16) -> Option<Vec<T>> {
        let mut left = 0;
        let mut right = self.segments.len();

        while left < right {
            let mid = left + (right - left) / 2;
            let segment = &self.segments[mid];

            if port < segment.start {
                right = mid;
            } else if port > segment.end {
                left = mid + 1;
            } else {
                return Some(self.segments[mid].value.clone());
            }
        }
        None
    }
}

impl<T: Clone + Debug> Display for SegmentMap<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for segment in &self.segments {
            writeln!(f, "{}-{}: {:?}", segment.start, segment.end, segment.value)?;
        }
        Ok(())
    }
}

pub fn parse_u16_range_list_to_port_pairs(
    port_str: impl AsRef<str>,
    strict: bool,
) -> Option<Vec<(u16, u16)>> {
    let port_str = port_str.as_ref();
    let mut port_pair = Vec::new();
    let mut ports = port_str.split(",");
    while let Some(mut p) = ports.next() {
        p = p.trim();
        if let Ok(port) = p.parse::<u16>() {
            port_pair.push((port, port));
        } else {
            let range = p.split("-").collect::<Vec<&str>>();
            if range.len() != 2 {
                if strict {
                    return None;
                }
                continue;
            }

            if let (Some(start_str), Some(end_str)) = (range.get(0), range.get(1)) {
                if let (Ok(start), Ok(end)) = (start_str.parse::<u16>(), end_str.parse::<u16>()) {
                    port_pair.push((start, end));
                } else if strict {
                    return None;
                }
            }
        }
    }
    Some(port_pair)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        let mut mapper = SegmentMap::new();
        mapper.add_range(8080, 9090, vec![0]);
        mapper.add_single(9000, vec![1]);
        mapper.merge_segments();

        assert_eq!(mapper.find(8081), Some(0));
        assert_eq!(mapper.find(8999), Some(0));
        assert_eq!(mapper.find(9000), Some(1));
        assert_eq!(mapper.find(9001), Some(2));
        assert_eq!(mapper.find(9090), Some(2));
        assert_eq!(mapper.find(8079), None);
        assert_eq!(mapper.find(9091), None);
    }

    #[test]
    fn test_overlapping_ranges() {
        let mut mapper = SegmentMap::new();
        mapper.add_range(175, 180, vec![0]);
        mapper.add_range(150, 250, vec![1]);
        mapper.add_range(100, 200, vec![2]);
        mapper.add_range(120, 150, vec![3]);
        // 100-119: 2, 120-149: 2,3 150: 2,3,1 151-174: 1,2 175-180: 2, 1, 0, 181-200: 2, 1, 201-250: 1
        mapper.merge_segments();

        assert_eq!(mapper.find(120), Some(1));
        assert_eq!(mapper.find(160), Some(3));
        assert_eq!(mapper.find(177), Some(4));
        assert_eq!(mapper.find(185), Some(5));
        assert_eq!(mapper.find(220), Some(6));
        assert_eq!(mapper.find(251), None);

        let idx = mapper.find(120).unwrap();
        let mut port_value = mapper.segments[idx].value.clone();
        port_value.sort_unstable();
        assert_eq!(port_value.len(), 2);
        assert_eq!(port_value[0], 2);
        assert_eq!(port_value[1], 3);
    }

    #[test]
    fn test_single_ports() {
        let mut mapper = SegmentMap::new();
        mapper.add_single(8080, vec![0]);
        mapper.add_single(3306, vec![1]);
        mapper.add_single(5432, vec![2]);
        mapper.merge_segments();

        assert_eq!(mapper.find(8080), Some(2));
        assert_eq!(mapper.find(3306), Some(0));
        assert_eq!(mapper.find(5432), Some(1));
        assert_eq!(mapper.find(8081), None);
    }

    #[test]
    fn test_repeated_ports() {
        let mut mapper = SegmentMap::new();
        mapper.add_single(8080, vec![0]);
        mapper.add_single(8080, vec![1]);
        mapper.add_range(8080, 9090, vec![3]);
        mapper.merge_segments();

        assert_eq!(mapper.find(8080), Some(0));
        let idx = mapper.find(8080).unwrap();
        let mut port_value = mapper.segments[idx].value.clone();
        port_value.sort_unstable();
        assert_eq!(port_value.len(), 3);
        assert_eq!(port_value[0], 0);
        assert_eq!(port_value[1], 1);
        assert_eq!(port_value[2], 3);
    }
}
