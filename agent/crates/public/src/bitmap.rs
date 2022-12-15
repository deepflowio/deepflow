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

use std::ops::{Bound, RangeBounds, RangeInclusive};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    IndexOutOfBound,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Bitmap(Vec<u8>);

impl Bitmap {
    pub fn new(max_pos: usize, init_all_true: bool) -> Self {
        return Bitmap(vec![if init_all_true { 255 } else { 0 }; (max_pos / 8) + 1]);
    }

    pub fn get_raw(&self) -> &Vec<u8> {
        &self.0
    }

    pub fn get_raw_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    // if success,return old value
    pub fn set(&mut self, pos: usize, val: bool) -> Result<bool, Error> {
        if pos > self.get_max_pos() {
            return Err(Error::IndexOutOfBound);
        }

        let (idx, u_pos) = self.get_idx_pos(pos);
        let old = self.get_by_idx_pos(idx, u_pos);
        self.set_by_idx_pos(idx, u_pos, val);
        Ok(old)
    }

    pub fn set_range<R: RangeBounds<usize>>(&mut self, range: R, val: bool) -> Result<(), Error> {
        let start = if let Bound::Included(start) = range.start_bound() {
            *start
        } else {
            unreachable!();
        };

        let end = match range.end_bound() {
            Bound::Included(end) => *end,
            Bound::Excluded(end) => *end - 1,
            _ => unreachable!(),
        };
        if start > end {
            return Ok(());
        }
        if end > self.get_max_pos() {
            return Err(Error::IndexOutOfBound);
        }

        let (start_idx, start_u_pos) = self.get_idx_pos(start);
        let (end_idx, end_u_pos) = self.get_idx_pos(end);

        if start_idx == end_idx {
            self.mask_byte(start_idx, start_u_pos as usize..=end_u_pos as usize, val);
            return Ok(());
        }

        // set start_idx byte
        self.mask_byte(start_idx, start_u_pos as usize..=7, val);

        // set byte in (start_idx, end_idx)
        let v = if val { u8::MAX } else { 0 };
        for i in start_idx + 1..end_idx {
            self.0[i] = v;
        }

        // set end_idx byte
        self.mask_byte(end_idx, 0..=(end_u_pos) as usize, val);
        Ok(())
    }

    pub fn get(&self, pos: usize) -> Result<bool, Error> {
        if pos > self.get_max_pos() {
            return Err(Error::IndexOutOfBound);
        }
        let (idx, u_pos) = self.get_idx_pos(pos);
        Ok(self.get_by_idx_pos(idx, u_pos))
    }

    // max_pos equal to ((max/8)+1)*8-1, not equal the max, where max is new() first param.
    fn get_max_pos(&self) -> usize {
        self.0.len() * 8 - 1
    }

    // return vec index and u8 bit
    fn get_idx_pos(&self, pos: usize) -> (usize, u8) {
        (pos / 8, (pos % 8) as u8)
    }

    fn get_by_idx_pos(&self, idx: usize, u_pos: u8) -> bool {
        self.0.get(idx).unwrap() & (1 << u_pos) != 0
    }

    fn set_by_idx_pos(&mut self, idx: usize, u_pos: u8, val: bool) {
        if val {
            *(self.0.get_mut(idx).unwrap()) |= 1 << u_pos;
        } else {
            *(self.0.get_mut(idx).unwrap()) &= !(1 << u_pos);
        }
    }

    // bit_range must in [0, 7]
    fn mask_byte(&mut self, idx: usize, bit_range: RangeInclusive<usize>, val: bool) {
        let (start_pos, end_pos) = (*(bit_range.start()), *(bit_range.end()));
        if val {
            self.0[idx] |= ((1 << (end_pos + 1)) - (1 << start_pos)) as u8;
        } else {
            self.0[idx] &= !((1 << (end_pos + 1)) - (1 << start_pos)) as u8;
        };
    }
}

#[cfg(test)]
mod test {
    use super::Error;

    use super::Bitmap;

    #[test]
    fn test_bitmap() {
        let mut bit = Bitmap::new(12, false);
        assert_eq!(bit.get_max_pos(), 15);
        assert_eq!(bit.set(16, true).unwrap_err(), Error::IndexOutOfBound);

        for i in 0..16 {
            let old = bit.set(i, true).unwrap();
            assert_eq!(old, false);

            for j in 0..16 {
                if j <= i {
                    assert_eq!(bit.get(j).unwrap(), true)
                } else {
                    assert_eq!(bit.get(j).unwrap(), false)
                }
            }
        }

        for i in 0..16 {
            let old = bit.set(i, false).unwrap();
            assert_eq!(old, true);

            for j in 0..16 {
                if j <= i {
                    assert_eq!(bit.get(j).unwrap(), false)
                } else {
                    assert_eq!(bit.get(j).unwrap(), true)
                }
            }
        }

        // test set range
        let mut bit = Bitmap::new(64, false);
        let _ = bit.set_range(61..60, true);
        for i in 0..64 {
            assert_eq!(bit.get(i).unwrap(), false);
        }

        let _ = bit.set_range(60..=60, true);
        for i in 0..64 {
            if i == 60 {
                assert_eq!(bit.get(i).unwrap(), true);
            } else {
                assert_eq!(bit.get(i).unwrap(), false);
            }
        }

        let _ = bit.set_range(2..=7, true);
        for i in 0..64 {
            match i {
                2..=7 | 60 => assert_eq!(bit.get(i).unwrap(), true),
                _ => assert_eq!(bit.get(i).unwrap(), false),
            }
        }
        let _ = bit.set_range(8..18, true);
        for i in 0..64 {
            match i {
                2..=17 | 60 => assert_eq!(bit.get(i).unwrap(), true),
                _ => assert_eq!(bit.get(i).unwrap(), false),
            }
        }

        let _ = bit.set_range(20..=62, true);
        for i in 0..64 {
            match i {
                2..=17 | 20..=62 => assert_eq!(bit.get(i).unwrap(), true),
                _ => assert_eq!(bit.get(i).unwrap(), false),
            }
        }

        let _ = bit.set_range(30..53, false);
        for i in 0..64 {
            match i {
                2..=17 | 20..=29 | 53..=62 => assert_eq!(bit.get(i).unwrap(), true),
                _ => assert_eq!(bit.get(i).unwrap(), false),
            }
        }
    }
}
