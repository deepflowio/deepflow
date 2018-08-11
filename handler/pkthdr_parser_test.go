package handler

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/google/gopacket/pcapgo"
)

func testPcapExtract(t *testing.T, file string, expect string) {
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
		meta := NewMetaPktHdr(packet, 0, 0, net.ParseIP("0.0.0.0"))
		meta.Raw = nil
		if meta.String() != expect {
			t.Error(fmt.Sprintf("\nExcept:\n%s\nActual:\n%s\n", expect, meta))
			break
		}
	}
}

const (
	NORMAL_EXPECT = "Timestamp: 0 InPort: 0x0 PktLen: 114 Exporter: 0.0.0.0 L2End0: false L2End1: false EpData: 0x0 Raw: 0x0\n" +
		"    TnlData: {TunType:0 TunID:0 IpSrc:<nil> IpDst:<nil>}\n" +
		"    MacSrc: c8:8d:83:93:58:14 MacDst: 00:1b:21:bb:22:42 EthType: IPv4 Vlan: 0\n" +
		"    IpSrc: 172.20.1.106 IpDst: 172.18.0.4 Proto: UDP TTL: 63\n" +
		"    PortSrc: 20033 PortDst: 20033 PayloadLen: 72 TcpData: {Flags:0 Seq:0 Ack:0 WinSize:0 WinScale:0 SACKPermitted:false}"
)

func TestPktExtract(t *testing.T) {
	testPcapExtract(t, "pkthdr_parser_test.pcap", NORMAL_EXPECT)
}
