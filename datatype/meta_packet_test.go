package datatype

import (
	. "encoding/binary"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func loadPcap(file string) []RawPacket {
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
	for {
		packet, _, err := r.ReadPacketData()
		if err != nil || packet == nil {
			break
		}
		packets = append(packets, packet)
	}
	return packets
}

func TestParsePacket(t *testing.T) {
	da, _ := net.ParseMAC("00:1b:21:bb:22:42")
	sa, _ := net.ParseMAC("c8:8d:83:93:58:14")
	expected := &MetaPacket{
		PacketLen: 114,
		MacSrc:    MacIntFromBytes(sa),
		MacDst:    MacIntFromBytes(da),

		EthType:    layers.EthernetTypeIPv4,
		IpSrc:      BigEndian.Uint32(net.ParseIP("172.20.1.106").To4()),
		IpDst:      BigEndian.Uint32(net.ParseIP("172.18.0.4").To4()),
		Protocol:   layers.IPProtocolUDP,
		TTL:        63,
		PortSrc:    20033,
		PortDst:    20033,
		PayloadLen: 72,
	}
	packet := loadPcap("meta_packet.pcap")[0]
	actual := &MetaPacket{PacketLen: uint16(len(packet))}
	actual.Parse(packet)
	if result := cmp.Diff(expected, actual); result != "" {
		t.Error(result)
	}
}

func BenchmarkParsePacket(b *testing.B) {
	packets := loadPcap("meta_packet_test.pcap")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := packets[i%len(packets)]
		actual := &MetaPacket{PacketLen: uint16(len(packet))}
		actual.Parse(packet)
	}
}
