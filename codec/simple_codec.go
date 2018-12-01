package codec

import (
	"encoding/binary"

	"gitlab.x.lan/yunshan/droplet-libs/pool"
)

// buffered encoder
type SimpleEncoder struct {
	buf []byte

	pool.ReferenceCount
}

func (e *SimpleEncoder) WriteU8(v byte) {
	e.buf = append(e.buf, v)
}

func (e *SimpleEncoder) WriteU16(v uint16) {
	s := [2]byte{}
	binary.LittleEndian.PutUint16(s[:], v)
	e.buf = append(e.buf, s[:]...)
}

func (e *SimpleEncoder) WriteU32(v uint32) {
	s := [4]byte{}
	binary.LittleEndian.PutUint32(s[:], v)
	e.buf = append(e.buf, s[:]...)
}

func (e *SimpleEncoder) WriteU64(v uint64) {
	s := [8]byte{}
	binary.LittleEndian.PutUint64(s[:], v)
	e.buf = append(e.buf, s[:]...)
}

func (e *SimpleEncoder) WriteString255(v string) {
	e.buf = append(e.buf, byte(len(v)))
	e.buf = append(e.buf, []byte(v)...)
}

func (e *SimpleEncoder) WriteRawString(v string) {
	e.buf = append(e.buf, []byte(v)...)
}

func (e *SimpleEncoder) Reset() {
	e.buf = e.buf[:0]
}

func (e *SimpleEncoder) Bytes() []byte {
	return e.buf
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

func (d *SimpleDecoder) ReadU8() byte {
	d.offset++
	if d.offset > len(d.buf) {
		d.err++
		return 0
	}
	return d.buf[d.offset-1]
}

func (d *SimpleDecoder) ReadU16() uint16 {
	d.offset += 2
	if d.offset > len(d.buf) {
		d.err++
		return 0
	}
	return binary.LittleEndian.Uint16(d.buf[d.offset-2 : d.offset])
}

func (d *SimpleDecoder) ReadU32() uint32 {
	d.offset += 4
	if d.offset > len(d.buf) {
		d.err++
		return 0
	}
	return binary.LittleEndian.Uint32(d.buf[d.offset-4 : d.offset])
}

func (d *SimpleDecoder) ReadU64() uint64 {
	d.offset += 8
	if d.offset > len(d.buf) {
		d.err++
		return 0
	}
	return binary.LittleEndian.Uint64(d.buf[d.offset-8 : d.offset])
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

func (d *SimpleDecoder) Bytes() []byte {
	return d.buf
}

func (d *SimpleDecoder) String() string {
	return string(d.buf)
}
