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
		meta := &MetaPktHdr{}
		meta.Extract(packet, 0, 0, net.ParseIP("0.0.0.0"))
		if meta.String() != expect {
			t.Error(fmt.Sprintf("\nExcept: %s\nActual: %s\n", expect, meta))
			break
		}
	}
}

const (
	NORMAL_EXPECT = "TIME: 0 INPORT: 0x0 EXPORTER: 0.0.0.0 PKT_LEN: 114 IS_L2_END: false - false\n" +
		"    TUN_TYPE: 0 TUN_ID: 0 TUN_IP: <nil> -> <nil>\n" +
		"    MAC: c8:8d:83:93:58:14 -> 00:1b:21:bb:22:42 TYPE: 2048 VLAN: 0\n" +
		"    IP: 172.20.1.106 -> 172.18.0.4 PROTO: 17 TTL: 63\n" +
		"    PORT: 20033 -> 20033 PAYLOAD_LEN: 72 FLAGS: 0 SEQ: 0 - 0 WIN: 0 WIN_SCALE: 0 SACK_PREMIT: false"
)

func TestPktExtract(t *testing.T) {
	testPcapExtract(t, "pkthdr_parser_test.pcap", NORMAL_EXPECT)
}
