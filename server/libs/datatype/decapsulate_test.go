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
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_ERSPAN_OR_TEB)
	expected := &TunnelInfo{
		Src:    IPv4Int(BigEndian.Uint32(net.ParseIP("172.28.25.108").To4())),
		Dst:    IPv4Int(BigEndian.Uint32(net.ParseIP("172.28.28.70").To4())),
		MacSrc: 0xbdf819ff,
		MacDst: 0x22222222,
		Id:     0,
		Type:   TUNNEL_TYPE_ERSPAN_OR_TEB,
		Tier:   1,
	}

	packets, _ := loadPcap("decapsulate_erspan1.pcap")
	packet1 := packets[0]
	packet2 := packets[1]

	l2Len := 18
	actual := &TunnelInfo{}
	offset := actual.Decapsulate(packet1, l2Len, bitmap)
	expectedOffset := IP_HEADER_SIZE + GRE_HEADER_SIZE
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedErspanI: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
	}
	actual = &TunnelInfo{}
	actual.Decapsulate(packet2, l2Len, bitmap)
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedErspanI: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
	}
}

func TestDecapsulateErspanII(t *testing.T) {
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_ERSPAN_OR_TEB)
	expected := &TunnelInfo{
		Src:    IPv4Int(BigEndian.Uint32(net.ParseIP("2.2.2.2").To4())),
		Dst:    IPv4Int(BigEndian.Uint32(net.ParseIP("1.1.1.1").To4())),
		MacSrc: 0xf1e20101,
		MacDst: 0xf1e20112,
		Id:     100,
		Type:   TUNNEL_TYPE_ERSPAN_OR_TEB,
		Tier:   1,
	}

	packets, _ := loadPcap("decapsulate_test.pcap")
	packet1 := packets[0]
	packet2 := packets[1]

	l2Len := 14
	actual := &TunnelInfo{}
	offset := actual.Decapsulate(packet1, l2Len, bitmap)
	expectedOffset := 50 - l2Len
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedErspanII: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
	}
	actual = &TunnelInfo{}
	actual.Decapsulate(packet2, l2Len, bitmap)
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedErspanII: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
		t.Error(expected)
		t.Error(actual)
	}
}

func TestDecapsulateIII(t *testing.T) {
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_ERSPAN_OR_TEB)
	expected := &TunnelInfo{
		Src:    IPv4Int(BigEndian.Uint32(net.ParseIP("172.16.1.103").To4())),
		Dst:    IPv4Int(BigEndian.Uint32(net.ParseIP("10.30.101.132").To4())),
		MacSrc: 0x60d19449,
		MacDst: 0x3ee959f5,
		Id:     0,
		Type:   TUNNEL_TYPE_ERSPAN_OR_TEB,
		Tier:   1,
	}

	packets, _ := loadPcap("decapsulate_test.pcap")
	packet := packets[3]

	l2Len := 14
	actual := &TunnelInfo{}
	offset := actual.Decapsulate(packet, l2Len, bitmap)
	expectedOffset := 54 - l2Len
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedErspanII: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
	}
}

func TestDecapsulateVxlan(t *testing.T) {
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_VXLAN)
	expected := &TunnelInfo{
		Src:    IPv4Int(BigEndian.Uint32(net.ParseIP("172.16.1.103").To4())),
		Dst:    IPv4Int(BigEndian.Uint32(net.ParseIP("172.20.1.171").To4())),
		MacSrc: 0xafda7679,
		MacDst: 0x3ddd88c3,
		Id:     123,
		Type:   TUNNEL_TYPE_VXLAN,
		Tier:   1,
	}

	packets, _ := loadPcap("decapsulate_test.pcap")
	packet := packets[2]

	l2Len := 14
	actual := &TunnelInfo{}
	offset := actual.Decapsulate(packet, l2Len, bitmap)
	expectedOffset := 50 - l2Len
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedErspanII: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
	}
}

func TestDecapsulateTencentGre(t *testing.T) {
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_TENCENT_GRE)
	expected := &TunnelInfo{
		Src:    IPv4Int(BigEndian.Uint32(net.ParseIP("10.19.0.21").To4())),
		Dst:    IPv4Int(BigEndian.Uint32(net.ParseIP("10.21.64.5").To4())),
		MacSrc: 0xbffac801,
		MacDst: 0x06246b71,
		Id:     0x10285,
		Type:   TUNNEL_TYPE_TENCENT_GRE,
		Tier:   1,
	}
	expectedOverlay := []byte{
		0x00, 0x00, 0x00, 0x00, 0x02, 0x85,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x28, 0x87, 0x93,
		0x40, 0x00, 0x40, 0x06, 0xa8, 0xe7,
		0x0a, 0x01, 0xfb, 0x29, 0x0a, 0x01, 0xfb, 0x29}

	packets, _ := loadPcap("tencent-gre.pcap")
	packet := packets[0]

	l2Len := 14
	actual := &TunnelInfo{}
	offset := actual.Decapsulate(packet, l2Len, bitmap)
	expectedOffset := 18
	if !reflect.DeepEqual(expected, actual) ||
		offset != expectedOffset ||
		!reflect.DeepEqual(expectedOverlay, packet[l2Len+expectedOffset:l2Len+expectedOffset+34]) {
		t.Errorf("expectedTencentGre: \n\ttunnel: %+v\n\tactual: %+v\n\toffset: %v\n\tactual: %v\n\toverlay: %x\n\tactual:  %x",
			expected, actual, expectedOffset, offset, expectedOverlay, packet[l2Len+18:l2Len+18+34])
	}
}

func TestDecapsulateTeb(t *testing.T) {
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_ERSPAN_OR_TEB)
	expected := &TunnelInfo{
		Src:    IPv4Int(BigEndian.Uint32(net.ParseIP("10.25.6.6").To4())),
		Dst:    IPv4Int(BigEndian.Uint32(net.ParseIP("10.25.59.67").To4())),
		MacSrc: 0x3503bca8,
		MacDst: 0x56aefcc6,
		Id:     0x2000000,
		Type:   TUNNEL_TYPE_ERSPAN_OR_TEB,
		Tier:   1,
	}

	packets, _ := loadPcap("vmware-gre-teb.pcap")
	packet := packets[2]

	l2Len := 14
	actual := &TunnelInfo{}
	offset := actual.Decapsulate(packet, l2Len, bitmap)
	expectedOffset := 28
	if !reflect.DeepEqual(expected, actual) || offset != expectedOffset {
		t.Errorf("expectedTeb: %+v\n actual: %+v, expectedOffset:%v, offset:%v",
			expected, actual, expectedOffset, offset)
	}
}

func TestDecapsulateIp6Vxlan(t *testing.T) {
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_VXLAN)
	expected := &TunnelInfo{
		Src:    IPv4Int(BigEndian.Uint32(net.ParseIP("0.0.2.63").To4())),
		Dst:    IPv4Int(BigEndian.Uint32(net.ParseIP("0.0.2.61").To4())),
		MacSrc: 0x3e7eda7d,
		MacDst: 0x3ebb1665,
		Id:     27,
		Type:   TUNNEL_TYPE_VXLAN,
		Tier:   1,
		IsIPv6: true,
	}
	packets, _ := loadPcap("ip6-vxlan.pcap")
	packet := packets[0]

	l2Len := 14
	actual := &TunnelInfo{}
	offset := actual.Decapsulate6(packet, l2Len, bitmap)
	expectedOffset := IP6_HEADER_SIZE + UDP_HEADER_SIZE + VXLAN_HEADER_SIZE
	if !reflect.DeepEqual(expected, actual) ||
		offset != expectedOffset {
		t.Errorf("expectedIp6Vxlan: \n\ttunnel: %+v\n\tactual: %+v\n\toffset: %v\n\tactual: %v\n",
			expected, actual, expectedOffset, offset)
	}
}

func TestDecapsulateIpIp(t *testing.T) {
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_IPIP)
	expected := &TunnelInfo{
		Src:    IPv4Int(BigEndian.Uint32(net.ParseIP("10.162.42.93").To4())),
		Dst:    IPv4Int(BigEndian.Uint32(net.ParseIP("10.162.33.164").To4())),
		MacSrc: 0x027dc643,
		MacDst: 0x0027e67d,
		Type:   TUNNEL_TYPE_IPIP,
		Tier:   1,
	}
	packets, _ := loadPcap("ipip.pcap")
	packet := packets[0]

	l2Len := 18
	actual := &TunnelInfo{}
	offset := actual.Decapsulate(packet, l2Len, bitmap)
	expectedOffset := IP_HEADER_SIZE - l2Len
	if !reflect.DeepEqual(expected, actual) ||
		offset != expectedOffset {
		t.Errorf("expectedIpIP: \n\ttunnel: %+v\n\tactual: %+v\n\toffset: %v\n\tactual: %v\n",
			expected, actual, expectedOffset, offset)
		t.Errorf("Packet: %x", packet[offset:])
	}
}

func TestDecapsulateAll(t *testing.T) {
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_VXLAN, TUNNEL_TYPE_ERSPAN_OR_TEB)
	tunnelMap := map[TunnelType]bool{TUNNEL_TYPE_VXLAN: false, TUNNEL_TYPE_ERSPAN_OR_TEB: false}

	packets, _ := loadPcap("decapsulate_test.pcap")
	for _, packet := range packets {
		l2Len := 14
		actual := &TunnelInfo{}
		actual.Decapsulate(packet, l2Len, bitmap)
		tunnelMap[actual.Type] = true
	}

	for key, value := range tunnelMap {
		if !value {
			t.Errorf("expect %s but not exist.", TunnelType(key))
		}
	}
}

func BenchmarkDecapsulateTCP(b *testing.B) {
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_VXLAN)
	packet := [256]byte{}
	tunnel := &TunnelInfo{}
	packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE] = byte(IPProtocolTCP)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnel.Decapsulate(packet[:], 0, bitmap)
	}
}

func BenchmarkDecapsulateUDP(b *testing.B) {
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_VXLAN)
	packet := [256]byte{}
	tunnel := &TunnelInfo{}
	packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE] = byte(IPProtocolUDP)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnel.Decapsulate(packet[:], 0, bitmap)
	}
}

func BenchmarkDecapsulateUDP4789(b *testing.B) {
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_VXLAN)
	packet := [256]byte{}
	tunnel := &TunnelInfo{}
	packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE] = byte(IPProtocolUDP)
	packet[OFFSET_DPORT-ETH_HEADER_SIZE] = 4789 >> 8
	packet[OFFSET_DPORT-ETH_HEADER_SIZE+1] = 4789 & 0xFF

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnel.Decapsulate(packet[:], 0, bitmap)
	}
}

func BenchmarkDecapsulateVXLAN(b *testing.B) {
	bitmap := NewTunnelTypeBitmap(TUNNEL_TYPE_VXLAN)
	packet := [256]byte{}
	tunnel := &TunnelInfo{}
	packet[OFFSET_IP_PROTOCOL-ETH_HEADER_SIZE] = byte(IPProtocolUDP)
	packet[OFFSET_DPORT-ETH_HEADER_SIZE] = 4789 >> 8
	packet[OFFSET_DPORT-ETH_HEADER_SIZE+1] = 4789 & 0xFF
	packet[OFFSET_VXLAN_FLAGS-ETH_HEADER_SIZE] = 0x8

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunnel.Decapsulate(packet[:], 0, bitmap)
	}
}
