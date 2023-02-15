/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/libs/utils"
)

const PKT_CNT_INFINITE = 0

var log = logging.MustGetLogger(os.Args[0])

var Ifname = flag.String("i", "", "Specify interface name")
var StatsInterval = flag.Int("s", 0, "Specify stats interval, unit: second")
var SrcMac = flag.String("srcMac", "", "source MAC")
var DstMac = flag.String("dstMac", "", "source MAC")
var SrcIp = flag.String("srcIp", "", "source MAC")
var DstIp = flag.String("dstIp", "", "source MAC")
var EnableProfile = flag.Bool("p", true, "if enable Profile")
var PktCount = flag.Int("c", 0, "specify receive or send packet count, default 0 stand for forever")
var LogLevel = flag.String("l", "Info", "specify log level(ingore case)"+
	"[CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG], default is INFO")
var FrameNum = flag.Uint("n", 1024, "Specify the sum of umem blocks, must be power of 2, default is 1024")
var PayloadLen = flag.Uint("L", 0, "Specify packet payload length, default is 0, packet total length = payload + 42(udp) or 54(tcp)")
var Proto = flag.String("P", "udp", "Specify ip protocol(udp or tcp), default is udp")

// increase仅对dMac, dIp有效
func GeneratePacket(sMac, dMac, sIp, dIp string, increase int) []byte {
	buffer := gopacket.NewSerializeBuffer()
	lays := make([]gopacket.SerializableLayer, 0, 5)
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}

	srcMac, err := net.ParseMAC(sMac)
	if err != nil {
		fmt.Printf("error srcMac:%v", srcMac)
	}
	dstMac, err := net.ParseMAC(dMac)
	if err != nil {
		fmt.Printf("error dstMac:%v", dstMac)
	}
	dstMac[5] += byte(increase)
	log.Debugf("dstMac:%v", dstMac.String())
	eth := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	lays = append(lays, &eth)

	srcIp := net.ParseIP(sIp)
	dstIp := net.ParseIP(dIp)
	dstIp[15] += byte(increase)
	log.Debugf("dstIp:%v", dstIp.String())

	if *Proto == "udp" {
		ip := layers.IPv4{
			Version: 4, SrcIP: srcIp, DstIP: dstIp,
			Protocol: layers.IPProtocolUDP, TTL: 64,
			Checksum: 0x2222,
		}
		lays = append(lays, &ip)
		udp := layers.UDP{
			SrcPort:  layers.UDPPort(1111),
			DstPort:  layers.UDPPort(2222),
			Checksum: 0x2223,
		}
		udp.SetNetworkLayerForChecksum(&ip)
		lays = append(lays, &udp)
	} else {
		ip := layers.IPv4{
			Version: 4, SrcIP: srcIp, DstIP: dstIp,
			Protocol: layers.IPProtocolTCP, TTL: 64,
			Checksum: 0x3333,
		}
		lays = append(lays, &ip)
		tcp := layers.TCP{
			SrcPort:  layers.TCPPort(3333),
			DstPort:  layers.TCPPort(4444),
			Checksum: 0x3334,
		}
		tcp.SetNetworkLayerForChecksum(&ip)
		lays = append(lays, &tcp)
	}

	payload := make([]byte, *PayloadLen)
	lays = append(lays, gopacket.Payload(payload))
	gopacket.SerializeLayers(buffer, opt, lays...)
	pkt := buffer.Bytes()
	fmt.Printf("generate packet(len:%v):\n%s", len(pkt),
		hex.Dump(pkt[:utils.Min(len(pkt), 128)]))

	return pkt
}

func GetPktCount(count int) int {
	if count == 0 {
		return PKT_CNT_INFINITE
	}

	return count
}

func StartProfiler() {
	go func() {
		if err := http.ListenAndServe("0.0.0.0:8008", nil); err != nil {
			fmt.Println("Start pprof on http 0.0.0.0:8008 failed")
			os.Exit(1)
		}
	}()
}
