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

// FIXME：比较本实现和codec/prefix_varint_codec.go中的性能

/*
https://www.geeksforgeeks.org/count-trailing-zero-bits-using-lookup-table/

The lookup table solution is based on following concepts:

1. The solution assumes that negative numbers are stored in 2’s complement form
   which is true for most of the devices. If numbers are represented in 2’s
   complement form, then (x & -x) [Bitwise and of x and minus x] produces a number
   with only last set bit.
2. Once we get a number with only one bit set, we can find its position using
   lookup table. It makes use of the fact that the first 32 bit position values are
   relatively prime with 37, so performing a modulus division with 37 gives a
   unique number from 0 to 36 for each. These numbers may then be mapped to the
   number of zeros using a small lookup table.
*/

pub fn count_trailing_zeros32(x: u32) -> u8 {
    let lookup: [u8; 37] = [
        32, 0, 1, 26, 2, 23, 27, 0, 3, 16, 24, 30, 28, 11, 0, 13, 4, 7, 17, 0, 25, 22, 31, 15, 29,
        10, 12, 6, 0, 21, 14, 9, 5, 20, 8, 19, 18,
    ];
    let y: i64 = x as i64;
    let i = ((-y & y) % 37) as usize;
    return lookup[i];
}
