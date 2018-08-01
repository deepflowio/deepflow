package data

import (
	"encoding/binary"
	"net"
)

const MACLen = 6

type IP struct {
	ip    net.IP
	ipStr string
	ipInt uint32
}

func NewIPFromString(ipStr string) *IP {
	if ip := net.ParseIP(ipStr); ip != nil {
		if p := ip.To4(); len(p) != net.IPv4len { // not IPv4
			return nil
		}
		return &IP{ip, ipStr, binary.BigEndian.Uint32(ip.To4())}
	}
	return nil
}

func NewIPFromInt(ipInt uint32) *IP {
	ip := net.IPv4(byte(ipInt>>24), byte(ipInt>>16), byte(ipInt>>8), byte(ipInt))
	return &IP{ip, ip.String(), ipInt}
}

func (ip *IP) String() string {
	return ip.ipStr
}

func (ip *IP) Int() uint32 {
	return ip.ipInt
}

type MACAddr struct {
	addr    net.HardwareAddr
	addrStr string
	addrInt uint64
}

func NewMACAddrFromString(addrStr string) *MACAddr {
	if addr, err := net.ParseMAC(addrStr); err == nil {
		if len(addr) != MACLen {
			return nil
		}
		var b [8]byte
		copy(b[2:], addr)
		return &MACAddr{addr, addrStr, binary.BigEndian.Uint64(b[:])}
	}
	return nil
}

func NewMACAddrFromInt(addrInt uint64) *MACAddr {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], addrInt&0xFFFFFFFFFFFF)
	addr := net.HardwareAddr(b[2:])
	return &MACAddr{addr, addr.String(), addrInt}
}

func (m *MACAddr) String() string {
	return m.addrStr
}

func (m *MACAddr) Int() uint64 {
	return m.addrInt
}
