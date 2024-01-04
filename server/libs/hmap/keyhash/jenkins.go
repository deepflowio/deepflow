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

package keyhash

// Jenkins Wiki： https://en.wikipedia.org/wiki/Jenkins_hash_function
// 64位算法： https://blog.csdn.net/yueyedeai/article/details/17025265
// 32位算法： http://burtleburtle.net/bob/hash/integer.html

// Jenkins哈希的两个关键特性是：
//   1.雪崩性（更改输入参数的任何一位，就将引起输出有一半以上的位发生变化）
//   2.可逆性
// 目前我们仅用到雪崩性，来获得更好的分布

func Jenkins(hash uint64) int32 {
	hash = (hash << 21) - hash - 1
	hash = hash ^ (hash >> 24)
	hash = (hash + (hash << 3)) + (hash << 8) // hash * 265
	hash = hash ^ (hash >> 14)
	hash = (hash + (hash << 2)) + (hash << 4) // hash * 21
	hash = hash ^ (hash >> 28)
	hash = hash + (hash << 31)
	return int32(hash)
}

func Jenkins128(key0, key1 uint64) int32 {
	return Jenkins(key0) ^ Jenkins(key1)
}

func Jenkins32(hash uint32) int32 {
	hash = (hash << 11) - hash - 1
	hash = hash ^ (hash >> 12)
	hash = (hash + (hash << 3)) + (hash << 8) // hash * 265
	hash = hash ^ (hash >> 7)
	hash = (hash + (hash << 2)) + (hash << 4) // hash * 21
	hash = hash ^ (hash >> 14)
	hash = hash + (hash << 16)
	return int32(hash)
}

func JenkinsSlice(bs []byte, step int) uint32 {
	hash := uint32(0)
	for i := 0; i < len(bs); i += step {
		hash += uint32(bs[i])
		hash += hash << 10
		hash ^= hash >> 6
	}
	hash += hash << 3
	hash ^= hash >> 11
	hash += hash << 15
	return hash
}
