package datatype

import (
	. "encoding/binary"
	"net"
	"reflect"
	"testing"
)

func TestDecapsulate(t *testing.T) {
	expectedErspan := &TunnelInfo{
		Src:  IPv4Int(BigEndian.Uint32(net.ParseIP("172.16.1.103").To4())),
		Dst:  IPv4Int(BigEndian.Uint32(net.ParseIP("172.20.1.171").To4())),
		Id:   123,
		Type: TUNNEL_TYPE_ERSPAN,
	}
	expectedVxlan := &TunnelInfo{
		Src:  IPv4Int(BigEndian.Uint32(net.ParseIP("172.16.1.103").To4())),
		Dst:  IPv4Int(BigEndian.Uint32(net.ParseIP("172.20.1.171").To4())),
		Id:   123,
		Type: TUNNEL_TYPE_VXLAN,
	}

	packets, _ := loadPcap("decapsulate_test.pcap")
	packetErspan := packets[0]
	packetVxlan := packets[1]

	l2Len := 14
	actual := &TunnelInfo{}
	actual.Decapsulate(packetErspan[l2Len:])
	if !reflect.DeepEqual(expectedErspan, actual) {
		t.Errorf("expectedErspan: %+v\n actual: %+v", expectedErspan, actual)
	}
	actual = &TunnelInfo{}
	actual.Decapsulate(packetVxlan[l2Len:])
	if !reflect.DeepEqual(expectedVxlan, actual) {
		t.Errorf("expectedVxlan: %+v\n actual: %+v", expectedVxlan, actual)
	}
}
