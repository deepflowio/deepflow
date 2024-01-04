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

// reference: https://my.oschina.net/ifraincoat/blog/604415
package utils

func BKDRHash(base uint64, str string) uint64 {
	seed := uint64(131) // 31 131 1313 13131 131313 etc..
	hash := base
	for i := 0; i < len(str); i++ {
		hash = (hash * seed) + uint64(str[i])
	}
	return hash
}

func SDBMHash(base uint64, str string) uint64 {
	hash := base
	for i := 0; i < len(str); i++ {
		hash = uint64(str[i]) + (hash << 6) + (hash << 16) - hash
	}
	return hash
}

func DJBHash(base uint64, str string) uint64 {
	hash := base
	for i := 0; i < len(str); i++ {
		hash = ((hash << 5) + hash) + uint64(str[i])
	}
	return hash
}

func APHash(base uint64, str string) uint64 {
	hash := uint64(0xAAAAAAAA) + base
	for i := 0; i < len(str); i++ {
		if (i & 1) == 0 {
			hash ^= ((hash << 7) ^ uint64(str[i])*(hash>>3))
		} else {
			hash ^= (^((hash << 11) + uint64(str[i]) ^ (hash >> 5)))
		}
	}
	return hash
}
