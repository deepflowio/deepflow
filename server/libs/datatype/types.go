package datatype

import (
	. "encoding/binary"
)

type PacketFlag uint16

func (f PacketFlag) IsSet(flag PacketFlag) bool {
	return f&flag != 0
}

const (
	CFLAG_MAC0 PacketFlag = 1 << iota
	CFLAG_MAC1
	CFLAG_VLANTAG
	CFLAG_HEADER_TYPE

	CFLAG_IP0
	CFLAG_IP1
	CFLAG_PORT0
	CFLAG_PORT1

	CFLAG_TTL
	CFLAG_FLAGS_FRAG_OFFSET
	CFLAG_DATAOFF_IHL

	PFLAG_SRC_L3ENDPOINT
	PFLAG_DST_L3ENDPOINT
	PFLAG_SRC_ENDPOINT
	PFLAG_DST_ENDPOINT
	PFLAG_TUNNEL

	PFLAG_NONE PacketFlag = 0
	CFLAG_FULL            = 0x7FF
)

type IPv4Int = uint32 // not native byte order

type MacInt = uint64 // not native byte order

func MacIntFromBytes(bytes []byte) MacInt {
	return uint64(BigEndian.Uint32(bytes))<<16 | uint64(BigEndian.Uint16(bytes[4:]))
}
