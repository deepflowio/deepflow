package utils

import (
	"encoding/binary"
	"net"
)

func UintMin(x, y uint) uint {
	if x < y {
		return x
	}
	return y
}

func Mac2Uint64(mac net.HardwareAddr) uint64 {
	return uint64(binary.BigEndian.Uint16(mac[:]))<<32 | uint64(binary.BigEndian.Uint32(mac[2:]))
}

func Uint64ToMac(v uint64) net.HardwareAddr {
	bytes := [8]byte{}
	binary.BigEndian.PutUint64(bytes[:], v)
	return net.HardwareAddr(bytes[2:])
}
