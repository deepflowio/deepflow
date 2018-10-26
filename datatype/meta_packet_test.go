package datatype

import (
	"bytes"
	. "encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"

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

func TestParseArp(t *testing.T) {
	da, _ := net.ParseMAC("ac:2b:6e:b3:84:63")
	sa, _ := net.ParseMAC("52:54:00:33:c4:54")
	expected := &MetaPacket{
		InPort:    0,
		PacketLen: 60,
		MacSrc:    MacIntFromBytes(sa),
		MacDst:    MacIntFromBytes(da),

		EthType: layers.EthernetTypeARP,
		IpSrc:   BigEndian.Uint32(net.ParseIP("10.33.0.1").To4()),
		IpDst:   BigEndian.Uint32(net.ParseIP("10.33.0.105").To4()),
	}
	packet := loadPcap("arp.pcap")[0]
	actual := &MetaPacket{PacketLen: uint16(len(packet))}
	l2Len := actual.ParseL2(packet)
	actual.Parse(packet[l2Len:])
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("expected: %+v，actual: %+v", expected, actual)
	}
}

func TestParseInvalid(t *testing.T) {
	da, _ := net.ParseMAC("00:50:56:e9:32:74")
	sa, _ := net.ParseMAC("00:0c:29:15:0a:35")
	expected := &MetaPacket{
		InPort:    0,
		Invalid:   true,
		PacketLen: 36,
		MacSrc:    MacIntFromBytes(sa),
		MacDst:    MacIntFromBytes(da),

		EthType:  layers.EthernetTypeIPv4,
		IpSrc:    BigEndian.Uint32(net.ParseIP("192.168.227.152").To4()),
		IpDst:    BigEndian.Uint32(net.ParseIP("10.33.0.1").To4()),
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
	}
	packet := loadPcap("invalid.pcap")[0]
	actual := &MetaPacket{PacketLen: uint16(len(packet))}
	l2Len := actual.ParseL2(packet)
	actual.Parse(packet[l2Len:])
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("expected: %+v，actual: %+v", expected, actual)
	}
}

func TestParseTorPackets(t *testing.T) {
	var buffer bytes.Buffer
	packets := loadPcap("meta_packet_test.pcap")
	for _, packet := range packets {
		meta := &MetaPacket{InPort: 0x30000, PacketLen: uint16(len(packet))}
		l2Len := meta.ParseL2(packet)
		meta.Parse(packet[l2Len:])
		buffer.WriteString(meta.String() + "\n")
	}
	expectFile := "meta_packet_test.result"
	content, _ := ioutil.ReadFile(expectFile)
	expected := string(content)
	actual := buffer.String()
	if expected != actual {
		ioutil.WriteFile("actual.txt", []byte(actual), 0644)
		t.Error(fmt.Sprintf("Inconsistent with %s, written to actual.txt", expectFile))
	}
}

func TestParseIspPackets(t *testing.T) {
	expectInPorts := [...]uint32{0x10002, 0x10001, 0x10002, 0x10002, 0x10001, 0x10002, 0x10002, 0x10002, 0x10002, 0x10002}
	actualInPorts := [len(expectInPorts)]uint32{}
	packets := loadPcap("isp.pcap")
	for i, packet := range packets {
		meta := &MetaPacket{PacketLen: uint16(len(packet))}
		l2Len := meta.ParseL2(packet)
		meta.Parse(packet[l2Len:])
		actualInPorts[i] = meta.InPort
	}
	if !reflect.DeepEqual(actualInPorts, expectInPorts) {
		t.Errorf("Expect %+v, but actual %+v", expectInPorts, actualInPorts)
	}
}

func TestAcquireReleaseClone(t *testing.T) {
	p := AcquireMetaPacket()
	p.AddReferenceCount()
	ReleaseMetaPacket(p)
	ReleaseMetaPacket(p)
	expected := &MetaPacket{PacketLen: 10086}
	dup := CloneMetaPacket(expected)
	if p != dup { // pointer compare
		t.Error("Expected same pointer but actually not")
	}
	if dup.PacketLen != expected.PacketLen {
		t.Error("Not duplicated")
	}
}

func BenchmarkParsePacket(b *testing.B) {
	packets := loadPcap("meta_packet_test.pcap")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := packets[i%len(packets)]
		actual := &MetaPacket{PacketLen: uint16(len(packet))}
		l2Len := actual.ParseL2(packet)
		actual.Parse(packet[l2Len:])
	}
}

func BenchmarkQinQ(b *testing.B) {
	packets := loadPcap("isp.pcap")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := packets[i%len(packets)]
		actual := &MetaPacket{PacketLen: uint16(len(packet))}
		l2Len := actual.ParseL2(packet)
		actual.Parse(packet[l2Len:])
	}
}
