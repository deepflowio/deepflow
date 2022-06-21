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
