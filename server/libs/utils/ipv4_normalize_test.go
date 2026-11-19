package utils

import (
	"net"
	"testing"
)

func TestIpToUint32Representations(t *testing.T) {
	for _, ip := range []net.IP{net.IP{192, 0, 2, 1}, net.ParseIP("192.0.2.1"), net.ParseIP("::ffff:192.0.2.1")} {
		if got := IpToUint32(ip); got != 0xc0000201 {
			t.Fatalf("%v converted to %#x", ip, got)
		}
	}
	for _, ip := range []net.IP{nil, net.ParseIP("2001:db8::1"), net.IP{1, 2}} {
		if IpToUint32(ip) != 0 {
			t.Fatal("invalid/non-IPv4 input accepted")
		}
	}
}
