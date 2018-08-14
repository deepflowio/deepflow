package utils

import (
	"encoding/binary"
	"net"
	"strings"
)

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

func IpToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func IpFromUint32(ipInt uint32) net.IP {
	ip := make([]byte, net.IPv4len)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip
}

func Bool2Int(b bool) int {
	if b {
		return 1
	}
	return 0
}
