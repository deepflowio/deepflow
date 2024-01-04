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

// reference github.com/golang/protobuf/proto encode.go decode.go
package codec

import (
	"errors"
	"io"
)

// encode
func (e *SimpleEncoder) encodeVarint(x uint64) {
	for x >= 1<<7 {
		e.buf = append(e.buf, uint8(x&0x7f|0x80))
		x >>= 7
	}
	e.buf = append(e.buf, uint8(x))
}

func (e *SimpleEncoder) WriteZigzagU32(v uint32) {
	e.encodeVarint(uint64((v << 1) ^ uint32((int32(v) >> 31))))
}

func (e *SimpleEncoder) WriteZigzagU64(v uint64) {
	e.encodeVarint(uint64((v << 1) ^ uint64((int64(v) >> 63))))
}

func (e *SimpleEncoder) WriteVarintU32(v uint32) {
	e.encodeVarint(uint64(v))
}

func (e *SimpleEncoder) WriteVarintU64(v uint64) {
	e.encodeVarint(v)
}

// decode
func (d *SimpleDecoder) ReadZigzagU32() uint32 {
	x := d.DecodeVarint()
	return (uint32(x) >> 1) ^ uint32((int32(x&1)<<31)>>31)
}

func (d *SimpleDecoder) ReadZigzagU64() uint64 {
	x := d.DecodeVarint()
	return (x >> 1) ^ uint64((int64(x&1)<<63)>>63)
}

func (d *SimpleDecoder) ReadVarintU32() uint32 {
	return (uint32)(d.DecodeVarint())
}

func (d *SimpleDecoder) ReadVarintU64() uint64 {
	return d.DecodeVarint()
}

func (d *SimpleDecoder) DecodeVarint() uint64 {
	i := d.offset
	buf := d.buf

	if i >= len(buf) {
		d.err++
		return 0
	} else if buf[i] < 0x80 {
		d.offset++
		return uint64(buf[i])
	} else if len(buf)-i < 10 {
		v, _ := d.decodeVarintSlow()
		return v
	}

	var b uint64
	// we already checked the first byte
	x := uint64(buf[i]) - 0x80
	i++

	b = uint64(buf[i])
	i++
	x += b << 7
	if b&0x80 == 0 {
		goto done
	}
	x -= 0x80 << 7

	b = uint64(buf[i])
	i++
	x += b << 14
	if b&0x80 == 0 {
		goto done
	}
	x -= 0x80 << 14

	b = uint64(buf[i])
	i++
	x += b << 21
	if b&0x80 == 0 {
		goto done
	}
	x -= 0x80 << 21

	b = uint64(buf[i])
	i++
	x += b << 28
	if b&0x80 == 0 {
		goto done
	}
	x -= 0x80 << 28

	b = uint64(buf[i])
	i++
	x += b << 35
	if b&0x80 == 0 {
		goto done
	}
	x -= 0x80 << 35

	b = uint64(buf[i])
	i++
	x += b << 42
	if b&0x80 == 0 {
		goto done
	}
	x -= 0x80 << 42

	b = uint64(buf[i])
	i++
	x += b << 49
	if b&0x80 == 0 {
		goto done
	}
	x -= 0x80 << 49

	b = uint64(buf[i])
	i++
	x += b << 56
	if b&0x80 == 0 {
		goto done
	}
	x -= 0x80 << 56

	b = uint64(buf[i])
	i++
	x += b << 63
	if b&0x80 == 0 {
		goto done
	}
	// x -= 0x80 << 63 // Always zero.

	d.err++
	return 0

done:
	d.offset = i
	return x
}

func (d *SimpleDecoder) decodeVarintSlow() (x uint64, err error) {
	i := d.offset
	l := len(d.buf)

	for shift := uint(0); shift < 64; shift += 7 {
		if i >= l {
			err = io.ErrUnexpectedEOF
			d.err++
			return
		}
		b := d.buf[i]
		i++
		x |= (uint64(b) & 0x7F) << shift
		if b < 0x80 {
			d.offset = i
			return
		}
	}

	// The number is too large to represent in a 64-bit value.
	err = errors.New("decode: integer overflow")
	d.err++
	return
}
