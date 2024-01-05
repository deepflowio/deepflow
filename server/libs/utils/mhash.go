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

package utils

// this hash method is based on Murmurhash

func mhashRotate(x uint32, k uint) uint32 {
	return (x << k) | (x >> (32 - k))
}

func mhashAddInner(hash, data uint32) uint32 {
	if data == 0 {
		return hash
	}
	data *= 0xcc9e2d51
	data = mhashRotate(data, 15)
	data *= 0x1b873593
	return hash ^ data
}

func mhashAdd(hash, data uint32) uint32 {
	hash = mhashAddInner(hash, data)
	hash = mhashRotate(hash, 13)
	return hash*5 + 0xe6546b64
}

func mhashFinish(hash uint32) uint32 {
	hash ^= hash >> 16
	hash *= 0x85ebca6b
	hash ^= hash >> 13
	hash *= 0xc2b2ae35
	hash ^= hash >> 16
	return hash
}

func MurmurHashAdd(hash, data uint32) uint32 {
	return mhashAdd(hash, data)
}

func MurmurHashAddUint64(hash uint32, data uint64) uint32 {
	return mhashAdd(mhashAdd(hash, uint32(data)), uint32(data>>32))
}

func MurmurHashFinish(hash uint32) uint32 {
	return mhashFinish(hash)
}
