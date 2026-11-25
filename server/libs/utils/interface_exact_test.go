package utils

import (
	"net"
	"testing"
)

func TestFindInterfaceRejectsPartialAddresses(t *testing.T) {
	for _, input := range []string{"", "127", "0", "/8"} {
		if got := FindInterfaceByIp(input); got != nil {
			t.Fatalf("invalid address %q matched %v", input, got)
		}
	}
}

func TestFindInterfaceMatchesLocalAddress(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if FindInterfaceByIp(ip.String()) == nil {
				t.Fatalf("local address %s was not found", ip)
			}
			return
		}
	}
	t.Skip("no local IP address available")
}
