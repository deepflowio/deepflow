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
