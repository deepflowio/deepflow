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

// Jenkins Wiki： https://en.wikipedia.org/wiki/Jenkins_hash_function
// 64位算法： https://blog.csdn.net/yueyedeai/article/details/17025265
// 32位算法： http://burtleburtle.net/bob/hash/integer.html

// Jenkins哈希的两个关键特性是：
//   1.雪崩性（更改输入参数的任何一位，就将引起输出有一半以上的位发生变化）
//   2.可逆性

pub fn jenkins64(mut hash: u64) -> u64 {
    hash = hash
        .overflowing_shl(21)
        .0
        .overflowing_sub(hash)
        .0
        .overflowing_sub(1)
        .0;
    hash = hash ^ hash.overflowing_shr(24).0;
    hash = hash
        .overflowing_add(hash.overflowing_shl(3).0)
        .0
        .overflowing_add(hash.overflowing_shl(8).0)
        .0;
    hash = hash ^ hash.overflowing_shr(14).0;
    hash = hash
        .overflowing_add(hash.overflowing_shl(2).0)
        .0
        .overflowing_add(hash.overflowing_shl(4).0)
        .0;
    hash = hash ^ hash.overflowing_shr(28).0;
    hash = hash.overflowing_add(hash.overflowing_shl(31).0).0;

    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_jenkins64() {
        assert_eq!(
            jenkins64(1281291242888) ^ jenkins64(122345676892),
            17281198411619148719
        );
    }
}
