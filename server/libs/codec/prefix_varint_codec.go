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

// reference: https://github.com/stoklund/varint/blob/master/prefix_varint.cpp
package codec

import (
	"encoding/binary"
)

var de_Bruijn_lookup_trailing = [32]int{0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8, 31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9}

var de_Bruijn_lookup_leading = [32]int{31, 22, 30, 21, 18, 10, 29, 2, 20, 17, 15, 13, 9, 6, 28, 1, 23, 19, 11, 3, 16, 14, 7, 24, 12, 4, 8, 25, 5, 26, 27, 0}

func count_trailing_zeros_32(x uint32) int {
	return de_Bruijn_lookup_trailing[(((x&-x)*0x077cb531)&0xffffffff)>>27]
}

func count_leading_zeros_32(x uint32) int {
	x |= x >> 1
	x |= x >> 2
	x |= x >> 4
	x |= x >> 8
	x |= x >> 16
	return de_Bruijn_lookup_leading[((x*0x07c4acdd)&0xffffffff)>>27]
}

func count_leading_zeros_64(x uint64) int {
	if x>>32 == 0 {
		return 32 + count_leading_zeros_32(uint32(x&0xffffffff))
	}
	return count_leading_zeros_32(uint32(x >> 32))
}

func (e *SimpleEncoder) WritePrefixU64(x uint64) {
	bits := 64 - count_leading_zeros_64(x|1)
	bytes := 1 + (bits-1)/7

	if bits > 56 {
		e.buf = append(e.buf, 0)
		bytes = 8
	} else {
		x = (2*x + 1) << (uint(bytes) - 1)
	}
	for n := 0; n < bytes; n++ {
		e.buf = append(e.buf, uint8(x&0xff))
		x >>= 8
	}
}

func bytesToUint64(b []byte) uint64 {
	var r uint64
	for i := 0; i < len(b); i++ {
		r |= (uint64(b[i]) << uint(8*i))
	}
	return r
}

func (d *SimpleDecoder) ReadPrefixU64() uint64 {
	length := 1 + count_trailing_zeros_32(uint32(d.buf[d.offset])|0x100)
	if length < 9 {
		unused := uint(64 - 8*length)
		d.offset += length
		if len(d.buf)-d.offset+length > 7 {
			return binary.LittleEndian.Uint64(d.buf[d.offset-length:]) << unused >> (unused + uint(length))
		}
		return bytesToUint64(d.buf[d.offset-length:d.offset]) << unused >> (unused + uint(length))

	} else {
		d.offset += length
		return binary.LittleEndian.Uint64(d.buf[d.offset-length+1 : d.offset])
	}
}
