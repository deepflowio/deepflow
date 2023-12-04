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

use std::ops::Range;

#[derive(Debug)]
pub struct RingBuf<T> {
    buf: Vec<T>,
    r_ptr: usize,
    w_ptr: usize,
    is_pow_2: bool,
}

pub enum RingBufSlice<'a, T> {
    Slice(&'a [T]),
    Vec(Vec<T>),
}

impl<'a, T> RingBufSlice<'a, T> {
    pub fn to_slice(&'a self) -> &'a [T] {
        match self {
            RingBufSlice::Slice(s) => s,
            RingBufSlice::Vec(s) => s.as_slice(),
        }
    }
}

impl<T> RingBuf<T> {
    pub fn new(cap: usize) -> Self {
        assert_ne!(cap, 0);
        Self {
            buf: Vec::with_capacity(cap),
            r_ptr: 0,
            w_ptr: 0,
            is_pow_2: cap & (cap - 1) == 0,
        }
    }

    fn mask_cap_to_idx(&self, v: usize) -> usize {
        if self.is_pow_2 {
            v & (self.cap() - 1)
        } else {
            v % self.cap()
        }
    }

    fn write_ptr_to_idx(&self) -> usize {
        self.mask_cap_to_idx(self.w_ptr)
    }

    pub fn len(&self) -> usize {
        self.w_ptr - self.r_ptr
    }

    pub fn cap(&self) -> usize {
        self.buf.capacity()
    }

    pub fn is_full(&self) -> bool {
        self.cap() == self.len()
    }

    pub fn push(&mut self, v: T) {
        let idx = self.write_ptr_to_idx();

        if self.buf.len() == self.buf.capacity() {
            let _ = std::mem::replace(&mut self.buf[idx], v);
        } else {
            self.buf.push(v);
        }
        if self.is_full() {
            self.r_ptr += 1;
        }
        self.w_ptr += 1;
    }

    pub fn extend(&mut self, v: impl IntoIterator<Item = T>) {
        for i in v {
            self.push(i);
        }
    }

    // write ptr add n directly, against the tcp reassemble, use for preserve buffer when recv the seq number not consequent
    // can not exceed the cap
    pub fn perserve_n(&mut self, n: usize)
    where
        T: Default + Clone,
    {
        if n + self.len() > self.cap() {
            panic!("ringbuf preserve_n out of cap");
        }

        if n + self.buf.len() <= self.buf.capacity() {
            self.buf.extend(vec![T::default(); n]);
        } else if self.buf.len() != self.buf.capacity() {
            self.buf
                .extend(vec![T::default(); self.buf.capacity() - self.buf.len()]);
        }
        self.w_ptr += n;
    }

    // can not exceed the length
    pub fn extend_from_offset(&mut self, off: usize, v: impl IntoIterator<Item = T>) {
        if off > self.len() {
            panic!("ringbuf extend_from_offset idx out of length");
        }

        if off == self.len() {
            self.extend(v);
            return;
        }

        let base_ptr = self.r_ptr;
        let mut count = 0;
        for i in v {
            let off_ptr = base_ptr + off + count;
            let idx = self.mask_cap_to_idx(off_ptr);
            let _ = std::mem::replace(&mut self.buf[idx], i);

            if off_ptr == self.w_ptr {
                if self.is_full() {
                    self.r_ptr += 1;
                }
                self.w_ptr += 1;
            }

            count += 1;
        }
    }

    // drain will not drop the ele immediately
    pub fn drain_n(&mut self, n: usize) {
        if n > self.len() {
            panic!("ringbuf drain_n out of length");
        }
        self.r_ptr += n;
    }

    pub fn to_range_vec(&self, range: Range<usize>) -> RingBufSlice<T>
    where
        T: Clone,
    {
        let Range { start, end } = range;
        if start > self.len() || end > self.len() {
            panic!("ringbuf to_vec out of length");
        }
        if start == end {
            return RingBufSlice::Vec(vec![]);
        }
        let (start_idx, end_idx) = (
            self.mask_cap_to_idx(self.r_ptr + start),
            self.mask_cap_to_idx(self.r_ptr + end - 1),
        );
        if end_idx > start_idx {
            RingBufSlice::Slice(&(self.buf.as_slice())[start_idx..=end_idx])
        } else {
            let b = self.buf.as_slice();
            let mut v: Vec<T> = (&b[start_idx..]).iter().cloned().collect();
            v.extend_from_slice(&b[..=end_idx]);
            println!();
            RingBufSlice::Vec(v)
        }
    }

    pub fn pop_n(&mut self, n: usize) -> Vec<T>
    where
        T: Clone,
    {
        if n > self.len() {
            panic!("ringbuf drain_n out of length");
        }
        let v = match self.to_range_vec(0..n) {
            RingBufSlice::Slice(s) => s.to_vec(),
            RingBufSlice::Vec(v) => v,
        };
        self.r_ptr += n;
        v
    }

    pub fn to_vec(&self) -> Vec<T>
    where
        T: Clone,
    {
        match self.to_range_vec(0..(self.len())) {
            RingBufSlice::Slice(s) => Vec::from_iter(s.iter().map(|v| v.clone())),
            RingBufSlice::Vec(v) => v,
        }
    }
}

#[cfg(test)]
mod test {
    use super::RingBuf;
    fn loop_extend(v: &mut Vec<i32>, s: &[i32]) {
        for i in s {
            if v.len() < v.capacity() {
                v.push(*i);
            } else {
                v.remove(0);
                v.push(*i);
            }
        }
    }
    fn test_extend(cap: usize) {
        let mut r = RingBuf::new(cap);
        let array = [0, 1, 2, 3, 4, 5, 6, 7];
        r.extend(array.clone());

        let mut v = Vec::with_capacity(cap);
        loop_extend(&mut v, &array.clone());

        assert_eq!(r.to_vec(), v);
        match r.to_range_vec(0..8) {
            crate::ringbuf::RingBufSlice::Slice(s) => assert_eq!(s, v.as_slice()),
            crate::ringbuf::RingBufSlice::Vec(_) => unreachable!(),
        }

        let array2 = [11, 22, 33, 44, 55, 66];
        r.extend(array2.clone());
        loop_extend(&mut v, &array2.clone());

        assert_eq!(r.to_vec(), v);
        match r.to_range_vec(0..cap) {
            crate::ringbuf::RingBufSlice::Slice(_) => unreachable!(),
            crate::ringbuf::RingBufSlice::Vec(c) => assert_eq!(c, v),
        }

        let array3 = [111, 222, 333, 444, 555, 666];

        r.extend(array3.clone());
        loop_extend(&mut v, &array3.clone());
        assert_eq!(r.to_vec(), v);
        match r.to_range_vec(0..cap) {
            crate::ringbuf::RingBufSlice::Slice(c) => assert_eq!(c, v.as_slice()),
            crate::ringbuf::RingBufSlice::Vec(c) => assert_eq!(c, v),
        }
    }

    fn test_pop_n(cap: usize) {
        let mut r = RingBuf::new(cap);
        let array = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        r.extend(array.clone());

        let mut v = Vec::with_capacity(cap);
        loop_extend(&mut v, &array);

        let v1 = r.pop_n(cap / 3);
        let v2 = v.split_off(cap / 3);
        assert_eq!(v1, v);
        v = v2;

        let v1 = r.pop_n(cap / 3);
        let _ = v.split_off(cap / 3);
        assert_eq!(v1, v);
    }

    #[test]
    fn test_extend_all() {
        test_extend(8);
        test_extend(10);
    }

    #[test]
    fn test_pop_all() {
        test_pop_n(8);
        test_pop_n(10);
    }
}
