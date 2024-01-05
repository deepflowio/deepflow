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

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PortRange(u32);

#[derive(Clone, Copy, PartialEq)]
enum PortStatus {
    RangeNone,
    RangeIn,
    RangeEdge,
    RangeLeft,
    RangeRight,
}

impl PortRange {
    pub const ZERO: PortRange = PortRange(0);

    pub fn new(min: u16, max: u16) -> PortRange {
        return PortRange((min as u32) << 16 | max as u32);
    }
    pub fn min(&self) -> u16 {
        return (self.0 >> 16) as u16;
    }
    pub fn max(&self) -> u16 {
        return (self.0 & 0xffff) as u16;
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.min(), self.max())
    }
}

impl TryFrom<&str> for PortRange {
    type Error = String;
    fn try_from(f: &str) -> Result<Self, Self::Error> {
        let ports: Vec<&str> = f.split("-").collect();
        if ports.len() < 2 {
            let port = f.parse::<u16>();
            if port.is_err() {
                return Err(format!("Invalid port {}: {}.\n", f, port.unwrap_err()));
            }
            let port = port.unwrap();
            return Ok(PortRange::new(port, port));
        }
        let min = ports[0].parse::<u16>();
        let max = ports[1].parse::<u16>();
        if min.is_err() || max.is_err() {
            return Err(format!("Invalid port {}.\n", f));
        }
        return Ok(PortRange::new(min.unwrap(), max.unwrap()));
    }
}

#[derive(Debug)]
pub struct PortRangeList(Vec<PortRange>);

impl PortRangeList {
    pub fn element(&self) -> &Vec<PortRange> {
        return &self.0;
    }
    fn create_table(&self, table: &mut [PortStatus; u16::MAX as usize + 1]) {
        for port in &self.0 {
            if port.min() == port.max() {
                table[port.min() as usize] = PortStatus::RangeEdge;
                continue;
            }
            if table[port.min() as usize] == PortStatus::RangeRight
                || table[port.min() as usize] == PortStatus::RangeEdge
            {
                table[port.min() as usize] = PortStatus::RangeEdge;
            } else {
                table[port.min() as usize] = PortStatus::RangeLeft;
            }

            if table[port.max() as usize] == PortStatus::RangeLeft
                || table[port.max() as usize] == PortStatus::RangeEdge
            {
                table[port.max() as usize] = PortStatus::RangeEdge;
            } else {
                table[port.max() as usize] = PortStatus::RangeRight;
            }

            for i in (port.min() as usize + 1)..(port.max() as usize) {
                if table[i as usize] == PortStatus::RangeNone {
                    table[i as usize] = PortStatus::RangeIn;
                }
            }
        }
    }

    pub fn interest(&self) -> Vec<PortRange> {
        if self.0.len() == 0 {
            return Vec::new();
        }

        let mut list: Vec<PortRange> = Vec::new();
        let mut table: [PortStatus; u16::MAX as usize + 1] = [PortStatus::RangeNone; 65536];
        self.create_table(&mut table);

        let mut last_port = -1;
        let mut port = 0;
        while port <= u16::MAX as i32 {
            let status = table[port as usize];

            match status {
                PortStatus::RangeEdge => {
                    if last_port >= 0
                        && last_port != port
                        && table[last_port as usize] != PortStatus::RangeNone
                    {
                        list.push(PortRange::new(last_port as u16, port as u16 - 1));
                    }
                    list.push(PortRange::new(port as u16, port as u16));
                    last_port = port + 1;
                }
                PortStatus::RangeLeft => {
                    if last_port >= 0
                        && last_port != port
                        && table[last_port as usize] != PortStatus::RangeNone
                    {
                        list.push(PortRange::new(last_port as u16, port as u16 - 1));
                    }
                    last_port = port;
                }
                PortStatus::RangeRight => {
                    if table[last_port as usize] != PortStatus::RangeNone {
                        list.push(PortRange::new(last_port as u16, port as u16));
                    }
                    last_port = port + 1;
                }
                _ => {}
            }
            port += 1;
        }
        return list;
    }
}

impl From<Vec<PortRange>> for PortRangeList {
    fn from(f: Vec<PortRange>) -> PortRangeList {
        return PortRangeList(f);
    }
}

impl From<&str> for PortRangeList {
    fn from(f: &str) -> PortRangeList {
        return PortRangeList::try_from(f.to_string()).unwrap();
    }
}

impl TryFrom<String> for PortRangeList {
    type Error = String;
    fn try_from(f: String) -> Result<Self, Self::Error> {
        if f.len() == 0 {
            return Ok(PortRangeList(vec![PortRange::new(0, 65535)]));
        }
        let mut list = Vec::new();
        let contexts: Vec<&str> = f.split(",").collect();
        for context in contexts {
            let ports = PortRange::try_from(context);
            if ports.is_err() {
                return Err(format!("Acl port parse: {}.\n", ports.unwrap_err()));
            }
            list.push(ports.unwrap());
        }

        // 从小到大排序
        list.sort_by(|a, b| a.min().partial_cmp(&b.min()).unwrap());
        // 合并连续的端口
        let mut delete_flags = vec![false; list.len()];
        let mut has_delete = false;
        for i in 0..list.len() {
            if i == list.len() - 1 {
                continue;
            }

            if list[i].max() + 1 >= list[i + 1].min() {
                let max = if list[i + 1].max() > list[i].max() {
                    list[i + 1].max()
                } else {
                    list[i].max()
                };
                list[i + 1] = PortRange::new(list[i].min(), max);
                delete_flags[i] = true;
                has_delete = true;
            }
        }

        if !has_delete {
            return Ok(PortRangeList(list));
        }
        let mut new_list = Vec::new();
        for (i, item) in list.iter().enumerate() {
            if delete_flags[i] {
                continue;
            }
            new_list.push(*item);
        }
        return Ok(PortRangeList(new_list));
    }
}

impl fmt::Display for PortRangeList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ports = self
            .0
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        write!(f, "[{}]", ports.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_range() {
        assert_eq!(
            PortRangeList(vec![PortRange::new(1, 2), PortRange::new(2, 3)]).interest(),
            vec![
                PortRange::new(1, 1),
                PortRange::new(2, 2),
                PortRange::new(3, 3)
            ]
        );
        assert_eq!(
            PortRangeList(vec![
                PortRange::new(6666, 6666),
                PortRange::new(6667, 6667),
                PortRange::new(6666, 6667),
                PortRange::new(8000, 8003),
                PortRange::new(8002, 8005),
                PortRange::new(8001, 8001),
                PortRange::new(8005, 8005)
            ])
            .interest(),
            vec![
                PortRange::new(6666, 6666),
                PortRange::new(6667, 6667),
                PortRange::new(8000, 8000),
                PortRange::new(8001, 8001),
                PortRange::new(8002, 8003),
                PortRange::new(8004, 8004),
                PortRange::new(8005, 8005)
            ]
        );
        assert_eq!(
            PortRangeList(vec![PortRange::new(1, 2), PortRange::new(2, 2)]).interest(),
            vec![PortRange::new(1, 1), PortRange::new(2, 2)]
        );
        assert_eq!(
            PortRangeList(vec![PortRange::new(1, 1), PortRange::new(1, 2)]).interest(),
            vec![PortRange::new(1, 1), PortRange::new(2, 2)]
        );
        assert_eq!(
            PortRangeList(vec![PortRange::new(1, 1), PortRange::new(2, 2)]).interest(),
            vec![PortRange::new(1, 1), PortRange::new(2, 2)]
        );
        assert_eq!(
            PortRangeList(vec![PortRange::new(1, 10), PortRange::new(5, 8)]).interest(),
            vec![
                PortRange::new(1, 4),
                PortRange::new(5, 8),
                PortRange::new(9, 10)
            ]
        );
        assert_eq!(
            PortRangeList(vec![
                PortRange::new(1, 10),
                PortRange::new(9, 15),
                PortRange::new(10, 20)
            ])
            .interest(),
            vec![
                PortRange::new(1, 8),
                PortRange::new(9, 9),
                PortRange::new(10, 10),
                PortRange::new(11, 15),
                PortRange::new(16, 20)
            ]
        );
        assert_eq!(
            PortRangeList(vec![
                PortRange::new(1, 10),
                PortRange::new(9, 15),
                PortRange::new(10, 20),
                PortRange::new(11, 18)
            ])
            .interest(),
            vec![
                PortRange::new(1, 8),
                PortRange::new(9, 9),
                PortRange::new(10, 10),
                PortRange::new(11, 15),
                PortRange::new(16, 18),
                PortRange::new(19, 20)
            ]
        );
        assert_eq!(
            PortRangeList(vec![
                PortRange::new(1, 100),
                PortRange::new(10, 90),
                PortRange::new(20, 80),
                PortRange::new(30, 70),
                PortRange::new(40, 60)
            ])
            .interest(),
            vec![
                PortRange::new(1, 9),
                PortRange::new(10, 19),
                PortRange::new(20, 29),
                PortRange::new(30, 39),
                PortRange::new(40, 60),
                PortRange::new(61, 70),
                PortRange::new(71, 80),
                PortRange::new(81, 90),
                PortRange::new(91, 100)
            ]
        );
        assert_eq!(
            PortRangeList(vec![
                PortRange::new(1, 1),
                PortRange::new(2, 2),
                PortRange::new(3, 3),
                PortRange::new(3, 100),
                PortRange::new(80, 80),
                PortRange::new(200, 300)
            ])
            .interest(),
            vec![
                PortRange::new(1, 1),
                PortRange::new(2, 2),
                PortRange::new(3, 3),
                PortRange::new(4, 79),
                PortRange::new(80, 80),
                PortRange::new(81, 100),
                PortRange::new(200, 300)
            ]
        );
        assert_eq!(
            PortRangeList(vec![PortRange::new(1000, 1000), PortRange::new(0, 65535)]).interest(),
            vec![
                PortRange::new(0, 999),
                PortRange::new(1000, 1000),
                PortRange::new(1001, 65535)
            ]
        );
    }

    #[test]
    fn test_port_range_list() {
        assert_eq!(
            PortRangeList::from("10,3-7,8,31-40,20-30").0,
            vec![
                PortRange::new(3, 8),
                PortRange::new(10, 10),
                PortRange::new(20, 40)
            ]
        );
        assert_eq!(
            PortRangeList::from("100-200,200-400").0,
            vec![PortRange::new(100, 400)]
        );
        assert_eq!(
            PortRangeList::from("102,100,101").0,
            vec![PortRange::new(100, 102)]
        );
        assert_eq!(
            PortRangeList::from("100-400,200-300").0,
            vec![PortRange::new(100, 400)]
        );
        assert_eq!(
            PortRangeList::from("200-300,100-400").0,
            vec![PortRange::new(100, 400)]
        );
        assert_eq!(
            PortRangeList::from("100-400,100-300,100-500").0,
            vec![PortRange::new(100, 500)]
        );
        assert_eq!(
            PortRangeList::from("200-400,100-400,300-400").0,
            vec![PortRange::new(100, 400)]
        );
    }
}
