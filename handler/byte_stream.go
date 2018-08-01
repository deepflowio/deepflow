package handler

import (
	"encoding/binary"
)

type ByteStream []byte

func (s *ByteStream) Field(len int) []byte {
	retval := (*s)[:len]
	*s = (*s)[len:]
	return retval
}

func (s *ByteStream) U8() uint8 {
	retval := uint8((*s)[0])
	*s = (*s)[1:]
	return retval
}

func (s *ByteStream) U16() uint16 {
	retval := binary.BigEndian.Uint16(*s)
	*s = (*s)[2:]
	return retval
}

func (s *ByteStream) U32() uint32 {
	retval := binary.BigEndian.Uint32(*s)
	*s = (*s)[4:]
	return retval
}

func (s *ByteStream) U64() uint64 {
	retval := binary.BigEndian.Uint64(*s)
	*s = (*s)[8:]
	return retval
}
