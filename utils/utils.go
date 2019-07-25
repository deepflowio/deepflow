package utils

import (
	. "encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"
	"time"
	"unsafe"
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

func GetIpHash(ip net.IP) uint32 {
	ipHash := uint32(0)
	for i := 0; i < len(ip); i += 4 {
		ipHash ^= *(*uint32)(unsafe.Pointer(&ip[i]))
	}
	return ipHash
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

func IpNetmaskFromStringCIDR(ipStr string) (net.IP, uint32, error) {
	_, r, err := net.ParseCIDR(ipStr)
	if err != nil {
		return nil, 0, err
	}
	maskInt, _ := r.Mask.Size()
	return r.IP, uint32(maskInt), nil
}

func IPv4ToBinary(ip uint32) string {
	var buf [32]byte
	for i := uint32(0); i < 32; i++ {
		if ip&(1<<i) != 0 {
			buf[31-i] = '1'
		} else {
			buf[31-i] = '0'
		}
	}
	return string(buf[:])
}

func IPv6ToBinary(ip net.IP) string {
	if len(ip) != 16 {
		panic(fmt.Sprintf("Invalid IPv6 address %v", ip))
	}
	var buf [128]byte
	for i := uint8(0); i < 128; i++ {
		if ip[15-i/8]&(1<<(i%8)) != 0 {
			buf[127-i] = '1'
		} else {
			buf[127-i] = '0'
		}
	}
	return string(buf[:])
}
