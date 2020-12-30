package datatype

import (
	. "encoding/binary"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"

	. "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PacketLen = int

func loadPcap(file string) ([]RawPacket, []PacketLen) {
	var f *os.File
	cwd, _ := os.Getwd()
	if strings.Contains(cwd, "datatype") {
		f, _ = os.Open(file)
	} else { // dlv
		f, _ = os.Open("datatype/" + file)
	}
	defer f.Close()

	r, _ := pcapgo.NewReader(f)
	var packets []RawPacket
	var packetLens []PacketLen
	for {
		packet, ci, err := r.ReadPacketData()
		if err != nil || packet == nil {
			break
		}
		packetLens = append(packetLens, ci.Length)
		if len(packet) > 128 {
			packets = append(packets, packet[:128])
		} else {
			packets = append(packets, packet)
		}
	}
	return packets, packetLens
}

func TestDecapsulateErspanI(t *testing.T) {
	expected := &TunnelInfo{
		Src:  IPv4Int(BigEndian.Uint32(net.ParseIP("172.28.25.108").To4())),
		Dst:  IPv4Int(BigEndian.Uint32(net.ParseIP("172.28.28.70").To4())),
		Id:   0,
		Type: TUNNEL_TYPE_ERSPAN,
		Tier: 1,
	}

	packets, _ := loadPcap("decapsulate_erspan1.pcap")
	packet1 := packets[0]
	packet2 := packets[1]

	l2Len := 18
	actual := &TunnelInfo{}
	offset := actual.Decapsulate(packet1[l2Len:], TUNNEL_TYPE_ERSPAN)
	expectedOffset := 20 + 8 // IP_HEADER_SIZE + GRE_HEADER_SIZE
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedErspanI: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
	}
	actual = &TunnelInfo{}
	actual.Decapsulate(packet2[l2Len:], TUNNEL_TYPE_ERSPAN)
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedErspanI: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
	}
}

func TestDecapsulateErspanII(t *testing.T) {
	expected := &TunnelInfo{
		Src:  IPv4Int(BigEndian.Uint32(net.ParseIP("2.2.2.2").To4())),
		Dst:  IPv4Int(BigEndian.Uint32(net.ParseIP("1.1.1.1").To4())),
		Id:   100,
		Type: TUNNEL_TYPE_ERSPAN,
		Tier: 1,
	}

	packets, _ := loadPcap("decapsulate_test.pcap")
	packet1 := packets[0]
	packet2 := packets[1]

	l2Len := 14
	actual := &TunnelInfo{}
	offset := actual.Decapsulate(packet1[l2Len:], TUNNEL_TYPE_ERSPAN)
	expectedOffset := 50 - l2Len
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedErspanII: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
	}
	actual = &TunnelInfo{}
	actual.Decapsulate(packet2[l2Len:], TUNNEL_TYPE_ERSPAN)
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedErspanII: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
	}
}

func TestDecapsulateIII(t *testing.T) {
	expected := &TunnelInfo{
		Src:  IPv4Int(BigEndian.Uint32(net.ParseIP("172.16.1.103").To4())),
		Dst:  IPv4Int(BigEndian.Uint32(net.ParseIP("10.30.101.132").To4())),
		Id:   0,
		Type: TUNNEL_TYPE_ERSPAN,
		Tier: 1,
	}

	packets, _ := loadPcap("decapsulate_test.pcap")
	packet := packets[3]

	l2Len := 14
	actual := &TunnelInfo{}
	offset := actual.Decapsulate(packet[l2Len:], TUNNEL_TYPE_ERSPAN)
	expectedOffset := 54 - l2Len
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedErspanII: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
	}
}

func TestDecapsulateVxlan(t *testing.T) {
	expected := &TunnelInfo{
		Src:  IPv4Int(BigEndian.Uint32(net.ParseIP("172.16.1.103").To4())),
		Dst:  IPv4Int(BigEndian.Uint32(net.ParseIP("172.20.1.171").To4())),
		Id:   123,
		Type: TUNNEL_TYPE_VXLAN,
		Tier: 1,
	}

	packets, _ := loadPcap("decapsulate_test.pcap")
	packet := packets[2]

	l2Len := 14
	actual := &TunnelInfo{}
	offset := actual.Decapsulate(packet[l2Len:], TUNNEL_TYPE_VXLAN)
	expectedOffset := 50 - l2Len
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedErspanII: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
	}
}

func BenchmarkDecapsulateTCP(b *testing.B) {
	packet := [256]byte{}
	tunnel := &TunnelInfo{}
	packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE] = byte(IPProtocolTCP)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnel.Decapsulate(packet[:], TUNNEL_TYPE_VXLAN)
	}
}

func BenchmarkDecapsulateUDP(b *testing.B) {
	packet := [256]byte{}
	tunnel := &TunnelInfo{}
	packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE] = byte(IPProtocolUDP)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnel.Decapsulate(packet[:], TUNNEL_TYPE_VXLAN)
	}
}

func BenchmarkDecapsulateUDP4789(b *testing.B) {
	packet := [256]byte{}
	tunnel := &TunnelInfo{}
	packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE] = byte(IPProtocolUDP)
	packet[OFFSET_DPORT-ETH_HEADER_SIZE] = 4789 >> 8
	packet[OFFSET_DPORT-ETH_HEADER_SIZE+1] = 4789 & 0xFF

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnel.Decapsulate(packet[:], TUNNEL_TYPE_VXLAN)
	}
}

func BenchmarkDecapsulateVXLAN(b *testing.B) {
	packet := [256]byte{}
	tunnel := &TunnelInfo{}
	packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE] = byte(IPProtocolUDP)
	packet[OFFSET_DPORT-ETH_HEADER_SIZE] = 4789 >> 8
	packet[OFFSET_DPORT-ETH_HEADER_SIZE+1] = 4789 & 0xFF
	packet[OFFSET_VXLAN_FLAGS-ETH_HEADER_SIZE] = 0x8

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnel.Decapsulate(packet[:], TUNNEL_TYPE_VXLAN)
	}
}
