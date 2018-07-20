package utils

import (
	"encoding/binary"
	"net"
	"strings"
)

func Mac2Uint32(mac net.HardwareAddr) uint32 {
	return binary.BigEndian.Uint32(mac[2:])
}

func Mac2Uint64(mac net.HardwareAddr) uint64 {
	return uint64(binary.BigEndian.Uint16(mac[:]))<<32 | uint64(binary.BigEndian.Uint32(mac[2:]))
}

func Uint64ToMac(v uint64) net.HardwareAddr {
	bytes := [8]byte{}
	binary.BigEndian.PutUint64(bytes[:], v)
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

// FIXME: net.IP和uint32的转换，需要寻找替代接口或优化性能
func IPToUInt32(ip net.IP) uint32 {
	if len(ip) == 0 {
		return 0
	}
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func UInt32ToIP(uip uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uip)
	return ip
}

func Bool2Int(b bool) int {
	if b {
		return 1
	}
	return 0
}
