package handler

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func testPcapExtract(file string, expect *MetaPacketHeader) string {
	var f *os.File
	cwd, _ := os.Getwd()
	if strings.Contains(cwd, "handler") {
		f, _ = os.Open(file)
	} else { // dlv
		f, _ = os.Open("handler/" + file)
	}
	defer f.Close()

	r, _ := pcapgo.NewReader(f)
	for {
		packet, _, err := r.ReadPacketData()
		if packet == nil || err != nil {
			break
		}
		meta := NewMetaPacketHeader(packet, 0, 0, net.ParseIP("0.0.0.0"))
		meta.Raw = nil
		if result := cmp.Diff(meta, expect); result != "" {
			return result
		}
	}
	return ""
}

func TestPktExtract(t *testing.T) {
	da, _ := net.ParseMAC("00:1b:21:bb:22:42")
	sa, _ := net.ParseMAC("c8:8d:83:93:58:14")
	expected := &MetaPacketHeader{
		PktLen:     114,
		Exporter:   net.ParseIP("0.0.0.0"),
		MacSrc:     sa,
		MacDst:     da,
		EthType:    layers.EthernetTypeIPv4,
		IpSrc:      net.ParseIP("172.20.1.106").To4(),
		IpDst:      net.ParseIP("172.18.0.4").To4(),
		Proto:      layers.IPProtocolUDP,
		TTL:        63,
		PortSrc:    20033,
		PortDst:    20033,
		PayloadLen: 72,
	}
	if result := testPcapExtract("packet_header_parser.pcap", expected); result != "" {
		t.Error(result)
	}
}
