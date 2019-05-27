package utils

import (
	. "encoding/binary"
	"math"
	"net"
	"strings"
	"time"
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

func Abs(n time.Duration) time.Duration {
	m := n >> 63
	return (n ^ m) - m
}

func IpToUint32(ip net.IP) uint32 {
	if ip.To4() == nil {
		return 0
	}
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

func MaskLenToNetmask(mask uint32) uint32 {
	return (math.MaxUint32) << (32 - mask)
}

func ParserStringIp(ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4
	}
	return ip
}

func ParserStringIpV4(ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	if ip = ip.To4(); ip == nil {
		return nil
	}
	return ip
}

func IpNetmaskFromStringCIDR(ipStr string) (uint32, uint32, error) {
	_, r, err := net.ParseCIDR(ipStr)
	if err != nil {
		return 0, 0, err
	}
	ipInt := BigEndian.Uint32(r.IP)
	maskInt, _ := r.Mask.Size()
	return ipInt, uint32(maskInt), nil
}
