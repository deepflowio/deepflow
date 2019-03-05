package datatype

import (
	"bytes"
	. "encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PacketLen = int

const MAX_ERR_PCAP_LEN = 10 * 1024

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

func loadErrorPcap(file string) ([]RawPacket, []PacketLen) {
	var f *os.File
	cwd, _ := os.Getwd()
	if strings.Contains(cwd, "datatype") {
		f, _ = os.Open(file)
	} else { // dlv
		f, _ = os.Open("datatype/" + file)
	}
	defer f.Close()

	var packets []RawPacket
	var packetLens []PacketLen
	var packet RawPacket
	rawPcap := make(RawPacket, MAX_ERR_PCAP_LEN)
	f.Seek(0, io.SeekStart)
	n, err := f.Read(rawPcap)
	if err != nil || n == MAX_ERR_PCAP_LEN {
		return nil, nil
	}

	stream := NewByteStream(rawPcap[:n])
	if stream.Len() > 24 {
		stream.Skip(24)
	}

	for stream.Len() > 0 {
		stream.Skip(8)
		capLen, realLen := LittleEndian.Uint32(stream.Field(4)), LittleEndian.Uint32(stream.Field(4))
		packet = stream.Field(int(capLen))

		packetLens = append(packetLens, int(realLen))
		if len(packet) > 128 {
			packets = append(packets, packet[:128])
		} else {
			packets = append(packets, packet)
		}
	}
	return packets, packetLens
}

func TestParseArp(t *testing.T) {
	da, _ := net.ParseMAC("ac:2b:6e:b3:84:63")
	sa, _ := net.ParseMAC("52:54:00:33:c4:54")
	packets, packetLens := loadPcap("meta_packet_arp_test.pcap")
	packet := packets[0]
	actual := &MetaPacket{PacketLen: uint16(packetLens[0])}
	l2Len := actual.ParseL2(packet)
	expected := &MetaPacket{
		InPort:    0,
		PacketLen: 60,
		MacSrc:    MacIntFromBytes(sa),
		MacDst:    MacIntFromBytes(da),

		EthType:   layers.EthernetTypeARP,
		IpSrc:     BigEndian.Uint32(net.ParseIP("10.33.0.1").To4()),
		IpDst:     BigEndian.Uint32(net.ParseIP("10.33.0.105").To4()),
		RawHeader: packet[l2Len : l2Len+ARP_HEADER_SIZE],
	}
	actual.Parse(packet[l2Len:])
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("expected: %+v，actual: %+v", expected, actual)
	}
}

func TestParseIcmp(t *testing.T) {
	var buffer bytes.Buffer
	packets, packetLens := loadPcap("meta_packet_icmp_test.pcap")

	for index, packet := range packets {
		meta := &MetaPacket{InPort: 0x30000, PacketLen: uint16(packetLens[index])}
		l2Len := meta.ParseL2(packet)
		meta.Parse(packet[l2Len:])
		buffer.WriteString(meta.String() + "\n")
	}
	expectFile := "meta_packet_icmp_test.result"
	content, _ := ioutil.ReadFile(expectFile)
	expected := string(content)
	actual := buffer.String()
	if expected != actual {
		ioutil.WriteFile("actual_icmp.txt", []byte(actual), 0644)
		t.Error(fmt.Sprintf("Inconsistent with %s, written to actual_icmp.txt", expectFile))
	}
}

func TestParseL2(t *testing.T) {
	var buffer bytes.Buffer
	packets, packetLens := loadPcap("meta_packet_layer2_test.pcap")
	for index, packet := range packets {
		meta := &MetaPacket{InPort: 0x30000, PacketLen: uint16(packetLens[index])}
		l2Len := meta.ParseL2(packet)
		meta.Parse(packet[l2Len:])
		meta.RawHeader = nil
		buffer.WriteString(meta.String() + "\n")
	}
	expectFile := "meta_packet_layer2_test.result"
	content, _ := ioutil.ReadFile(expectFile)
	expected := string(content)
	actual := buffer.String()
	if expected != actual {
		ioutil.WriteFile("l2_actual.txt", []byte(actual), 0644)
		t.Error(fmt.Sprintf("Inconsistent with %s, written to l2_actual.txt", expectFile))
	}
}

func TestParseVlan(t *testing.T) {
	var buffer bytes.Buffer
	packets, packetLens := loadPcap("meta_packet_vlan_test.pcap")
	for index, packet := range packets {
		meta := &MetaPacket{PacketLen: uint16(packetLens[index])}
		l2Len := meta.ParseL2(packet)
		meta.Parse(packet[l2Len:])
		meta.RawHeader = nil
		buffer.WriteString(meta.String() + "\n")
	}
	expectFile := "meta_packet_vlan_test.result"
	content, _ := ioutil.ReadFile(expectFile)
	expected := string(content)
	actual := buffer.String()
	if expected != actual {
		ioutil.WriteFile("vlan_actual.txt", []byte(actual), 0644)
		t.Error(fmt.Sprintf("Inconsistent with %s, written to vlan_actual.txt", expectFile))
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
		IHL:      5,
		IpID:     0xE9A5,
	}
	packets, packetLens := loadPcap("meta_packet_tcp_invalid_test.pcap")
	packet := packets[0]
	actual := &MetaPacket{PacketLen: uint16(packetLens[0])}
	l2Len := actual.ParseL2(packet)
	actual.Parse(packet[l2Len:])
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("expected: %+v，actual: %+v", expected, actual)
	}
}

func TestParseTorPackets(t *testing.T) {
	var buffer bytes.Buffer
	packets, packetLens := loadPcap("meta_packet_tcp_udp_test.pcap")
	for index, packet := range packets {
		meta := &MetaPacket{InPort: 0x30000, PacketLen: uint16(packetLens[index])}
		l2Len := meta.ParseL2(packet)
		meta.Parse(packet[l2Len:])
		meta.RawHeader = nil
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
	packets, packetLens := loadPcap("meta_packet_isp_test.pcap")
	for i, packet := range packets {
		meta := &MetaPacket{PacketLen: uint16(packetLens[i])}
		l2Len := meta.ParseL2(packet)
		meta.Parse(packet[l2Len:])
		actualInPorts[i] = meta.InPort
	}
	if !reflect.DeepEqual(actualInPorts, expectInPorts) {
		t.Errorf("Expect %+v, but actual %+v", expectInPorts, actualInPorts)
	}
}

func TestParseErrorPackets(t *testing.T) {
	var buffer bytes.Buffer
	packets, packetLens := loadErrorPcap("all_error_pkts.pcap")

	for i, packet := range packets {
		meta := &MetaPacket{PacketLen: uint16(packetLens[i])}
		l2Len := meta.ParseL2(packet)
		meta.Parse(packet[l2Len:])
		buffer.WriteString(meta.String() + "\n")
	}
	expectFile := "meta_error_packet_test.result"
	content, _ := ioutil.ReadFile(expectFile)
	expected := string(content)
	actual := buffer.String()
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Expect %+v, but actual %+v", expected, actual)
		ioutil.WriteFile("actual_error.txt", []byte(actual), 0644)
	}
}

func BenchmarkParsePacket(b *testing.B) {
	packets, packetLens := loadPcap("meta_packet_tcp_udp_test.pcap")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % len(packets)
		packet := packets[index]
		actual := &MetaPacket{PacketLen: uint16(packetLens[index])}
		l2Len := actual.ParseL2(packet)
		actual.Parse(packet[l2Len:])
		if actual.TcpData != nil {
			ReleaseTcpHeader(actual.TcpData)
		}
	}
}

func BenchmarkQinQ(b *testing.B) {
	packets, packetLens := loadPcap("meta_packet_isp_test.pcap")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % len(packets)
		packet := packets[index]
		actual := &MetaPacket{PacketLen: uint16(packetLens[index])}
		l2Len := actual.ParseL2(packet)
		actual.Parse(packet[l2Len:])
	}
}
