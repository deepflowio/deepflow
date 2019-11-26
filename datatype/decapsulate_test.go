package datatype

import (
	. "encoding/binary"
	"net"
	"reflect"
	"testing"
)

func TestDecapsulateErspanII(t *testing.T) {
	expected := &TunnelInfo{
		Src:  IPv4Int(BigEndian.Uint32(net.ParseIP("2.2.2.2").To4())),
		Dst:  IPv4Int(BigEndian.Uint32(net.ParseIP("1.1.1.1").To4())),
		Id:   100,
		Type: TUNNEL_TYPE_ERSPAN,
	}

	packets, _ := loadPcap("decapsulate_test.pcap")
	packet1 := packets[0]
	packet2 := packets[1]

	l2Len := 14
	actual := &TunnelInfo{}
	actual.Decapsulate(packet1[l2Len:])
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("expectedErspanII: %+v\n actual: %+v", expected, actual)
	}
	actual = &TunnelInfo{}
	actual.Decapsulate(packet2[l2Len:])
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("expectedErspanII: %+v\n actual: %+v", expected, actual)
	}
}

func TestDecapsulateIII(t *testing.T) {
	expected := &TunnelInfo{
		Src:  IPv4Int(BigEndian.Uint32(net.ParseIP("172.16.1.103").To4())),
		Dst:  IPv4Int(BigEndian.Uint32(net.ParseIP("10.30.101.132").To4())),
		Id:   0,
		Type: TUNNEL_TYPE_ERSPAN,
	}

	packets, _ := loadPcap("decapsulate_test.pcap")
	packet := packets[3]

	l2Len := 14
	actual := &TunnelInfo{}
	actual.Decapsulate(packet[l2Len:])
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("expectedErspanIII: %+v\n actual: %+v", expected, actual)
	}
}

func TestDecapsulateVxlan(t *testing.T) {
	expected := &TunnelInfo{
		Src:  IPv4Int(BigEndian.Uint32(net.ParseIP("172.16.1.103").To4())),
		Dst:  IPv4Int(BigEndian.Uint32(net.ParseIP("172.20.1.171").To4())),
		Id:   123,
		Type: TUNNEL_TYPE_VXLAN,
	}

	packets, _ := loadPcap("decapsulate_test.pcap")
	packet := packets[2]

	l2Len := 14
	actual := &TunnelInfo{}
	actual.Decapsulate(packet[l2Len:])
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("expectedVxlan: %+v\n actual: %+v", expected, actual)
	}
}
