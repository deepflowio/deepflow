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

package codec

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/deepflowio/deepflow/server/libs/pool"
)

// buffered encoder
type SimpleEncoder struct {
	buf []byte

	pool.ReferenceCount
}

type PBCodec interface {
	Size() int
	MarshalTo([]byte) (int, error)
	Unmarshal([]byte) error
}

func (e *SimpleEncoder) WritePB(v PBCodec) {
	offset := len(e.buf)
	size := v.Size()
	e.buf = append(e.buf, make([]byte, size+16)...) // 需要额申请16字节用于保留长度
	n, err := v.MarshalTo(e.buf[offset+4:])         // 预留4字节后面填写length
	if err != nil {
		panic(fmt.Sprintf("encode proto buf failed pb size %d, buffer size %d", v.Size(), len(e.buf)))
	}

	// 记录长度, 不包括自己的4字节
	binary.LittleEndian.PutUint32(e.buf[offset:], uint32(n))
	e.buf = e.buf[:offset+4+n]
	return
}

func (e *SimpleEncoder) WriteBool(v bool) {
	if v {
		e.buf = append(e.buf, 1)
	} else {
		e.buf = append(e.buf, 0)
	}
}

func (e *SimpleEncoder) WriteU8(v byte) {
	e.buf = append(e.buf, v)
}

func (e *SimpleEncoder) WriteU16(v uint16) {
	s := [2]byte{}
	binary.LittleEndian.PutUint16(s[:], v)
	e.buf = append(e.buf, s[:]...)
}

func (e *SimpleEncoder) WriteBigEndianU16(v uint16) {
	s := [2]byte{}
	binary.BigEndian.PutUint16(s[:], v)
	e.buf = append(e.buf, s[:]...)
}

func (e *SimpleEncoder) WriteU16Slice(vs []uint16) {
	e.WriteU32(uint32(len(vs)))
	s := [2]byte{}
	for _, v := range vs {
		binary.LittleEndian.PutUint16(s[:], v)
		e.buf = append(e.buf, s[:]...)
	}
}

func (e *SimpleEncoder) WriteU32(v uint32) {
	s := [4]byte{}
	binary.LittleEndian.PutUint32(s[:], v)
	e.buf = append(e.buf, s[:]...)
}

func (e *SimpleEncoder) WriteBigEndianU32(v uint32) {
	s := [4]byte{}
	binary.BigEndian.PutUint32(s[:], v)
	e.buf = append(e.buf, s[:]...)
}

func (e *SimpleEncoder) WriteU32Slice(vs []uint32) {
	e.WriteU32(uint32(len(vs)))
	s := [4]byte{}
	for _, v := range vs {
		binary.LittleEndian.PutUint32(s[:], v)
		e.buf = append(e.buf, s[:]...)
	}
}

func (e *SimpleEncoder) WriteU64(v uint64) {
	s := [8]byte{}
	binary.LittleEndian.PutUint64(s[:], v)
	e.buf = append(e.buf, s[:]...)
}

func (e *SimpleEncoder) WriteIPv6(v []byte) {
	if len(v) != 16 {
		panic(fmt.Sprintf("Invalid IPv6 Address: %v", v))
	}
	e.buf = append(e.buf, v...)
}

// 注意：将会截断至255字节
func (e *SimpleEncoder) WriteString255(v string) {
	length := len(v)
	if length > 255 {
		length = 255
	}

	e.buf = append(e.buf, byte(length))
	e.buf = append(e.buf, []byte(v)[:length]...)
}

func (e *SimpleEncoder) WriteRawString(v string) {
	e.buf = append(e.buf, []byte(v)...)
}

func (e *SimpleEncoder) WriteBytes(v []byte) {
	e.WriteU32(uint32(len(v)))
	e.buf = append(e.buf, v...)
}

func (e *SimpleEncoder) WriteBytesWithVarintLen(v []byte) {
	e.WriteVarintU32(uint32(len(v)))
	e.buf = append(e.buf, v...)
}

func (e *SimpleEncoder) ReplaceU16At(offset int, v uint16) {
	if offset+2 >= len(e.buf) {
		return
	}
	binary.LittleEndian.PutUint16(e.buf[offset:], v)
}

func (e *SimpleEncoder) ReplaceU32At(offset int, v uint32) {
	if offset+4 >= len(e.buf) {
		return
	}
	binary.LittleEndian.PutUint32(e.buf[offset:], v)
}

func (e *SimpleEncoder) ReplaceU64At(offset int, v uint64) {
	if offset+8 >= len(e.buf) {
		return
	}
	binary.LittleEndian.PutUint64(e.buf[offset:], v)
}

func (e *SimpleEncoder) Reset() {
	e.buf = e.buf[:0]
}

func (e *SimpleEncoder) Bytes() []byte {
	return e.buf
}

func (e *SimpleEncoder) RefOfString() string {
	if e.buf == nil {
		return ""
	}
	return *(*string)(unsafe.Pointer(&e.buf))
}

func (e *SimpleEncoder) String() string {
	return string(e.buf)
}

// pool of encoder
var simpleEncoderPool = pool.NewLockFreePool(func() interface{} {
	return new(SimpleEncoder)
})

func AcquireSimpleEncoder() *SimpleEncoder {
	e := simpleEncoderPool.Get().(*SimpleEncoder)
	e.ReferenceCount.Reset()
	return e
}

func ReleaseSimpleEncoder(encoder *SimpleEncoder) {
	if encoder.SubReferenceCount() {
		return
	}
	encoder.Reset()
	simpleEncoderPool.Put(encoder)
}

func PseudoCloneSimpleEncoder(encoder *SimpleEncoder) {
	encoder.AddReferenceCount()
}

// simple decoder
type SimpleDecoder struct {
	buf    []byte
	offset int
	err    int
}

func (d *SimpleDecoder) Init(buf []byte) {
	d.buf = buf
	d.offset = 0
	d.err = 0
}

func (d *SimpleDecoder) ReadPB(pb PBCodec) error {
	d.offset += 4
	if d.offset > len(d.buf) {
		d.err++
		return fmt.Errorf("offset(%d) out of buf len(%d)", d.offset, len(d.buf))
	}
	n := int(binary.LittleEndian.Uint32(d.buf[d.offset-4 : d.offset]))
	d.offset += n
	if d.offset > len(d.buf) {
		d.err++
		return fmt.Errorf("offset(%d) out of buf len(%d)", d.offset, len(d.buf))
	}
	err := pb.Unmarshal(d.buf[d.offset-n : d.offset])
	if err != nil {
		d.err++
		return err
	}

	return nil
}

func (d *SimpleDecoder) ReadU8() byte {
	d.offset++
	if d.offset > len(d.buf) {
		d.err++
		return 0
	}
	return d.buf[d.offset-1]
}

func (d *SimpleDecoder) ReadBool() bool {
	d.offset++
	if d.offset > len(d.buf) {
		d.err++
		return false
	}
	return d.buf[d.offset-1] == 1
}

func (d *SimpleDecoder) ReadU16() uint16 {
	d.offset += 2
	if d.offset > len(d.buf) {
		d.err++
		return 0
	}
	return binary.LittleEndian.Uint16(d.buf[d.offset-2 : d.offset])
}

func (d *SimpleDecoder) ReadU16Slice() []uint16 {
	l := int(d.ReadU32())
	if l == 0 {
		return nil
	}
	d.offset += l * 2
	if d.offset > len(d.buf) {
		d.err++
		return nil
	}

	ret := make([]uint16, 0, l)
	for i := l; i > 0; i-- {
		ret = append(ret, binary.LittleEndian.Uint16(d.buf[d.offset-2*i:d.offset-2*i+2]))
	}

	return ret
}

func (d *SimpleDecoder) ReadU32() uint32 {
	d.offset += 4
	if d.offset > len(d.buf) {
		d.err++
		return 0
	}
	return binary.LittleEndian.Uint32(d.buf[d.offset-4 : d.offset])
}

func (d *SimpleDecoder) ReadU32Slice() []uint32 {
	l := int(d.ReadU32())
	if l == 0 {
		return nil
	}
	d.offset += l * 4
	if d.offset > len(d.buf) {
		d.err++
		return nil
	}

	ret := make([]uint32, 0, l)
	for i := l; i > 0; i-- {
		ret = append(ret, binary.LittleEndian.Uint32(d.buf[d.offset-4*i:d.offset-4*i+4]))
	}

	return ret
}

func (d *SimpleDecoder) ReadU64() uint64 {
	d.offset += 8
	if d.offset > len(d.buf) {
		d.err++
		return 0
	}
	return binary.LittleEndian.Uint64(d.buf[d.offset-8 : d.offset])
}

func (d *SimpleDecoder) ReadIPv6(v []byte) {
	if len(v) != 16 {
		panic(fmt.Sprintf("IPv6 buffer length invalid: %d", len(v)))
	}
	d.offset += 16
	if d.offset > len(d.buf) {
		d.err++
		return
	}
	copy(v, d.buf[d.offset-16:d.offset])
}

func (d *SimpleDecoder) ReadIPv4(v net.IP) {
	if len(v) != 4 {
		panic(fmt.Sprintf("IPv4 buffer length invalid: %d", len(v)))
	}
	d.offset += 4
	if d.offset > len(d.buf) {
		d.err++
		return
	}
	copy(v, d.buf[d.offset-4:d.offset])
}

func (d *SimpleDecoder) ReadString255() string {
	l := int(d.ReadU8())
	d.offset += l
	if d.offset > len(d.buf) {
		d.err++
		return ""
	}
	return string(d.buf[d.offset-l : d.offset])
}

func (d *SimpleDecoder) ReadBytes() []byte {
	l := int(d.ReadU32())
	d.offset += l
	if d.offset > len(d.buf) {
		d.err++
		return nil
	}
	return d.buf[d.offset-l : d.offset]
}

func (d *SimpleDecoder) ReadBytesN(n int) []byte {
	d.offset += n
	if d.offset > len(d.buf) {
		d.err++
		return nil
	}
	return d.buf[d.offset-n : d.offset]
}

func (d *SimpleDecoder) ReadBytesWithVarintLen() []byte {
	l := int(d.ReadVarintU32())
	d.offset += l
	if d.offset > len(d.buf) {
		d.err++
		return nil
	}
	return d.buf[d.offset-l : d.offset]
}

func (d *SimpleDecoder) Offset() int {
	return d.offset
}

func (d *SimpleDecoder) Failed() bool {
	return d.err != 0
}

func (d *SimpleDecoder) IsEnd() bool {
	return d.offset >= len(d.buf)
}

func (d *SimpleDecoder) Bytes() []byte {
	return d.buf
}

func (d *SimpleDecoder) String() string {
	return string(d.buf)
}
