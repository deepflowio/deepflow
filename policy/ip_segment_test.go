package policy

import (
	"testing"
)

func TestIpSegmentSimple(t *testing.T) {
	ips := newIpSegment("192.168.10.12/23", 0)
	if ips.getMask() != 0xfffffe00 {
		t.Errorf("Error ipsegment 192.168.10.12/23 mask return 0x%x\n", ips.getMask())
	}
	if ips.getIp() != 0xc0a80a00 {
		t.Errorf("Error ipsegment 192.168.10.12/23 ip return 0x%x\n", ips.getIp())
	}

	ips = newIpSegment("0.0.0.0/0", 0)
	if ips.getMask() != 0 {
		t.Errorf("Error ipsegment 0.0.0.0/0 mask return 0x%x\n", ips.getMask())
	}
	if ips.getIp() != 0 {
		t.Errorf("Error ipsegment 0.0.0.0/0 ip return 0x%x\n", ips.getIp())
	}
}
