package utils

import (
	. "encoding/binary"
	"net"
	"strings"
)

func UintMin(x, y uint) uint {
	if x < y {
		return x
	}
	return y
}

func Mac2Uint64(mac net.HardwareAddr) uint64 {
	return uint64(BigEndian.Uint16(mac[:]))<<32 | uint64(BigEndian.Uint32(mac[2:]))
}

func Uint64ToMac(v uint64) net.HardwareAddr {
	bytes := [8]byte{}
	BigEndian.PutUint64(bytes[:], v)
	return net.HardwareAddr(bytes[2:])
}

func FindInterfaceByIp(ip string) *net.Interface {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if strings.Contains(addr.String(), ip) {
				return &iface
			}
		}
	}
	return nil
}

func IsMulticast(mac []byte) bool {
	return mac[0]&0x1 == 1
}

func Min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func Max(x, y int) int {
	if x > y {
		return x
	}
	return y
}

// 调用者保证入参是IPv4
func IpToUint32(ip net.IP) uint32 {
	return BigEndian.Uint32(ip)
}

func IpFromUint32(ipInt uint32) net.IP {
	ip := make([]byte, net.IPv4len)
	BigEndian.PutUint32(ip, ipInt)
	return ip
}

func Bool2Int(b bool) int {
	if b {
		return 1
	}
	return 0
}
