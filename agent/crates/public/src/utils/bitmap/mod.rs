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

use crate::bitmap::Bitmap;

// ports example: "1,2,3-55,6,77-888" ...
// if strict is true, must all parse correct, otherwise return None.
pub fn parse_port_string_to_bitmap(port_str: &String, strict: bool) -> Option<Bitmap> {
    let mut bitmap = Bitmap::new(u16::MAX as usize, false);
    let mut ports = port_str.split(",");

    while let Some(mut p) = ports.next() {
        p = p.trim();
        if let Ok(port) = p.parse::<u16>() {
            let _ = bitmap.set(port as usize, true);
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
                    let _ = bitmap.set_range(start as usize..=end as usize, true);
                } else if strict {
                    return None;
                }
            }
        }
    }
    Some(bitmap)
}
