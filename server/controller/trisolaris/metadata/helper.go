package metadata

import (
	"net"
)

func netmask2masklen(netmask string) (length int) {
	ipNet := net.ParseIP(netmask)
	if ipNet.To4() != nil {
		stringMask := net.IPMask(ipNet.To4())
		length, _ = stringMask.Size()
	} else if ipNet.To16() != nil {
		stringMask := net.IPMask(ipNet.To16())
		length, _ = stringMask.Size()
	}
	return
}

func judgNet(prefix string, netmask int) bool {
	if prefix == "" || netmask == 0 {
		return false
	}
	if prefix == "0.0.0.0" && netmask == 32 {
		return false
	} else if prefix == "::" && netmask == 128 {
		return false
	}

	return true
}
