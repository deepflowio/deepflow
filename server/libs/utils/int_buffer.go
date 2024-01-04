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

import (
	"encoding/binary"
)

type IntBuffer struct {
	buf []byte
}

func (b *IntBuffer) WriteU8(v byte) {
	b.buf = append(b.buf, v)
}

func (b *IntBuffer) WriteU16(v uint16) {
	s := [2]byte{}
	binary.LittleEndian.PutUint16(s[:], v)
	b.buf = append(b.buf, s[:]...)
}

func (b *IntBuffer) WriteU24(v uint32) {
	s := [4]byte{}
	binary.LittleEndian.PutUint32(s[:], v)
	b.buf = append(b.buf, s[:3]...)
}

func (b *IntBuffer) WriteU32(v uint32) {
	s := [4]byte{}
	binary.LittleEndian.PutUint32(s[:], v)
	b.buf = append(b.buf, s[:]...)
}

func (b *IntBuffer) WriteU48(v uint64) {
	s := [8]byte{}
	binary.LittleEndian.PutUint64(s[:], v)
	b.buf = append(b.buf, s[:6]...)
}

func (b *IntBuffer) WriteU64(v uint64) {
	s := [8]byte{}
	binary.LittleEndian.PutUint64(s[:], v)
	b.buf = append(b.buf, s[:]...)
}

func (b *IntBuffer) WriteString(v string) {
	b.buf = append(b.buf, []byte(v)...)
}

func (b *IntBuffer) Reset() {
	b.buf = b.buf[:0]
}

func (b *IntBuffer) String() string {
	return string(b.buf)
}
