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

package datatype

import (
	"encoding/binary"
)

type ByteStream struct {
	data   []byte
	offset int
}

func (s *ByteStream) Len() int {
	return len(s.data) - s.offset
}

func (s *ByteStream) Field(len int) []byte {
	s.offset += len
	return s.data[s.offset-len : s.offset]
}

func (s *ByteStream) U8() uint8 {
	s.offset++
	return uint8(s.data[s.offset-1])
}

func (s *ByteStream) U16() uint16 {
	s.offset += 2
	return binary.BigEndian.Uint16(s.data[s.offset-2:])
}

func (s *ByteStream) U32() uint32 {
	s.offset += 4
	return binary.BigEndian.Uint32(s.data[s.offset-4:])
}

func (s *ByteStream) U64() uint64 {
	s.offset += 8
	return binary.BigEndian.Uint64(s.data[s.offset-8:])
}

func (s *ByteStream) Skip(n int) {
	if n > 0 {
		s.offset += n
	}
}

func (s *ByteStream) Slice() []byte {
	return s.data[s.offset:]
}

func NewByteStream(data []byte) ByteStream {
	return ByteStream{data, 0}
}
