/*
 * Copyright (c) 2024 Yunshan Networks
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

package dedup

import (
	. "encoding/binary"
	"net"
	"testing"
	"time"

	. "github.com/google/gopacket/layers"
)

var dedupTable = NewPacketDedupMap("")

func m(mac string) net.HardwareAddr {
	m, _ := net.ParseMAC(mac)
	return m
}

func key2mac(key uint32) string {
	m := [6]byte{}
	BigEndian.PutUint32(m[2:], key)
	return net.HardwareAddr(m[:]).String()
}

func buildStubPacket(da, sa string, ethType EthernetType, payload uint32) []byte {
	packet := [128]byte{}
	copy(packet[:], m(da))
	copy(packet[6:], m(sa))
	BigEndian.PutUint16(packet[12:], uint16(ethType))
	BigEndian.PutUint32(packet[56:], payload)
	return packet[:]
}

func buildStubVlanTaggedPacket(da, sa string, vid uint16, ethType EthernetType, payload uint32) []byte {
	packet := [128]byte{}
	copy(packet[:], m(da))
	copy(packet[6:], m(sa))
	BigEndian.PutUint16(packet[12:], uint16(EthernetTypeDot1Q))
	BigEndian.PutUint16(packet[14:], vid&0xFFF)
	BigEndian.PutUint32(packet[60:], payload)
	return packet[:]
}

func TestMatched(t *testing.T) {
	da := "00:00:00:35:02:b0"
	sa := "00:00:00:fc:a4:0b"
	packet := buildStubPacket(da, sa, EthernetTypeIPv4, 1)

	if dedupTable.IsDuplicate(packet, 0) {
		t.Error("Should not match")
	}

	if !dedupTable.IsDuplicate(packet, 0) {
		t.Error("Should match")
	}

	if dedupTable.IsDuplicate(packet, 0) {
		t.Error("Should not match")
	}
}

func TestMultipleFlowsOnSameDirection(t *testing.T) {
	da := "00:00:00:fc:a4:0b"
	sa := "00:00:00:25:3f:63"
	packet := buildStubPacket(da, sa, EthernetTypeIPv4, 1)
	packet2 := buildStubPacket(da, sa, EthernetTypeARP, 2)

	dedupTable.IsDuplicate(packet, 0)
	dedupTable.IsDuplicate(packet2, 0)

	if !dedupTable.IsDuplicate(packet, 0) {
		t.Error("Should not match")
	}

	if !dedupTable.IsDuplicate(packet2, 0) {
		t.Error("Should not match")
	}
}

func TestPacketLoss(t *testing.T) {
	da := "00:00:00:fc:a4:0b"
	sa := "00:00:00:25:3f:63"
	packet := buildStubPacket(da, sa, EthernetTypeIPv4, 1)
	packet2 := buildStubPacket(da, sa, EthernetTypeIPv4, 2)

	dedupTable.IsDuplicate(packet, 0)
	dedupTable.IsDuplicate(packet2, 0)

	if !dedupTable.IsDuplicate(packet2, 0) {
		t.Error("Should not match")
	}
}

func TestHashCollision(t *testing.T) {
	da := "00:00:00:fc:a4:0b"
	sa := "00:00:00:25:3f:63"
	packet1 := buildStubPacket(da, sa, EthernetTypeIPv4, 0)
	BigEndian.PutUint32(packet1[48:], 1)

	packet2 := buildStubPacket(da, sa, EthernetTypeIPv4, 0)
	BigEndian.PutUint32(packet1[80:], 1790366114)

	if dedupTable.IsDuplicate(packet1, 0) {
		t.Error("Should not hit")
	}
	if dedupTable.IsDuplicate(packet2, 0) {
		t.Error("Should not hit")
	}
}

func TestVlanTagged(t *testing.T) {
	da := "00:00:00:fc:a4:0b"
	sa := "00:00:00:25:3f:63"
	packet1 := buildStubVlanTaggedPacket(da, sa, 1, EthernetTypeIPv4, 1)
	packet2 := buildStubVlanTaggedPacket(da, sa, 2, EthernetTypeIPv4, 1)
	if dedupTable.IsDuplicate(packet1, 0) {
		t.Error("Should not hit")
	}
	if !dedupTable.IsDuplicate(packet2, 0) {
		t.Error("Should hit")
	}
}

func TestChecksum(t *testing.T) {
	da := "00:00:00:fc:a4:0b"
	sa := "00:00:00:25:3f:63"
	packet := buildStubPacket(da, sa, EthernetTypeIPv4, 1)
	packet[14] = 5 // ihl
	packet[23] = byte(IPProtocolUDP)
	BigEndian.PutUint16(packet[40:], 0x0101)
	dedupTable.IsDuplicate(packet, 0)
	BigEndian.PutUint16(packet[40:], 0x1010)
	if !dedupTable.IsDuplicate(packet, 0) {
		t.Error("Should hit")
	}
}

func TestIgnoreTTL(t *testing.T) {
	da := "00:00:00:fc:a4:0b"
	sa := "00:00:00:25:3f:63"
	packet := buildStubPacket(da, sa, EthernetTypeIPv4, 2)
	packet[22] = 127 // ttl
	dedupTable.SetIgnoreTTL(true)
	dedupTable.IsDuplicate(packet, 0)
	packet[22] = 126 // ttl
	if !dedupTable.IsDuplicate(packet, 0) {
		t.Error("Should hit")
	}
	dedupTable.SetIgnoreTTL(false)
}

func TestTimeout(t *testing.T) {
	da := "00:00:00:fc:a4:0b"
	sa := "00:00:00:25:3f:63"
	packet := buildStubPacket(da, sa, EthernetTypeIPv4, 1)
	dedupTable.IsDuplicate(packet, 0)

	if dedupTable.IsDuplicate(packet, 110*time.Millisecond) {
		t.Error("Should not hit")
	}
}

func TestOverLimit(t *testing.T) {
	da := "00:00:00:fc:a4:0b"
	sa := "00:00:00:25:3f:63"
	for i := 0; i <= ELEMENTS_LIMIT+1; i++ {
		dedupTable.IsDuplicate(buildStubPacket(da, sa, EthernetTypeIPv4, uint32(i)), 0)
	}

	first := buildStubPacket(da, sa, EthernetTypeIPv4, 0)
	if dedupTable.IsDuplicate(first, 0) {
		t.Error("Should hit")
	}

	middle := buildStubPacket(da, sa, EthernetTypeIPv4, 500)
	if !dedupTable.IsDuplicate(middle, 0) {
		t.Error("Should hit")
	}
}

func BenchmarkDedupTable(b *testing.B) {
	packets := make([][]byte, 0)
	da := "00:00:00:fc:a4:0b"
	sa := "00:00:00:25:3f:63"
	for i := 0; i < 1<<16; i++ {
		for j := 1; j < 1000; j += 100 {
			packet := buildStubPacket(da, sa, EthernetType(i), uint32(j))
			packets = append(packets, packet)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dedupTable.IsDuplicate(packets[i%len(packets)], time.Duration(i)*2*time.Microsecond)
		if i >= 50000 {
			dedupTable.IsDuplicate(packets[(i-50000)%len(packets)], time.Duration(i)*2*time.Microsecond)
			i++
		}
	}
	b.Logf("counter: %v", dedupTable.GetCounter())
}
