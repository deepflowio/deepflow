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

use crate::bitmap::Bitmap;

// u16_range example: "1,2,3-55,6,77-888" ...
// if strict is true, must all parse correct, otherwise return None.
pub fn parse_u16_range_list_to_bitmap(port_str: impl AsRef<str>, strict: bool) -> Option<Bitmap> {
    let port_str = port_str.as_ref();
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

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::bitmap::Bitmap;

    use super::parse_u16_range_list_to_bitmap;

    fn assert_u16(b: &Bitmap, ports: &[u16]) {
        let mut h = HashMap::new();
        for i in ports {
            h.insert(*i, 0);
        }
        for i in 0..=u16::MAX {
            println!("{}", i);
            let v = b.get(i as usize).unwrap();
            assert_eq!(v, h.get(&i).is_some());
        }
    }

    #[test]
    fn test() {
        let p = "8";
        let b = parse_u16_range_list_to_bitmap(&String::from(p), false).unwrap();
        assert_u16(&b, &[8]);

        let p = "65535";
        let b = parse_u16_range_list_to_bitmap(&String::from(p), false).unwrap();
        assert_u16(&b, &[65535]);

        let p = " 1 , 1000-2000,  2,3, 8-99 ";
        let b = parse_u16_range_list_to_bitmap(&String::from(p), false).unwrap();
        assert_u16(
            &b,
            [
                &[1, 2, 3],
                (8 as u16..=99 as u16).collect::<Vec<u16>>().as_slice(),
                (1000 as u16..=2000 as u16).collect::<Vec<u16>>().as_slice(),
            ]
            .concat()
            .as_ref(),
        );

        let p = " 999,1000,1100,60000-99999";
        let b = parse_u16_range_list_to_bitmap(&String::from(p), false).unwrap();

        assert_u16(&b, &[999, 1000, 1100]);

        let p = "60001-99999";
        assert_eq!(parse_u16_range_list_to_bitmap(&String::from(p), true), None);
    }
}
