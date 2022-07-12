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

package idmap

type UBigIDMap interface {
	AddOrGetWithSlice(key []byte, hash uint32, value uint32, overwrite bool) (uint32, bool)
	GetWithSlice(key []byte, hash uint32) (uint32, bool)

	Size() int
	Width() int
	Clear()
}
