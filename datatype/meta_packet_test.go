package datatype

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

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
	var buffer bytes.Buffer
	packets := loadPcap("meta_packet_test.pcap")
	for _, packet := range packets {
		meta := &MetaPacket{PacketLen: uint16(len(packet))}
		meta.Parse(packet)
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

func BenchmarkParsePacket(b *testing.B) {
	packets := loadPcap("meta_packet_test.pcap")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := packets[i%len(packets)]
		actual := &MetaPacket{PacketLen: uint16(len(packet))}
		actual.Parse(packet)
	}
}

func BenchmarkQinQ(b *testing.B) {
	packets := loadPcap("isp.pcap")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := packets[i%len(packets)]
		actual := &MetaPacket{PacketLen: uint16(len(packet))}
		actual.Parse(packet)
	}
}
