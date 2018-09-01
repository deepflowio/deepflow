package dedup

import (
	. "encoding/binary"
	"time"
	"unsafe"

	"github.com/OneOfOne/xxhash"
	. "github.com/google/gopacket/layers"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("dedup")

func hashPacket(packet []byte) (uint32, uint64, PacketId) {
	var packetId PacketId
	id := uint64(0)

	if len(packet) < 18 { // ensure safety
		copy(packetId[:], packet)
		return xxhash.Checksum32(packetId[:]), id, packetId
	}

	ethType := EthernetType(BigEndian.Uint16(packet[12:]))
	if ethType == EthernetTypeDot1Q { // ignore vlan tag
		ethType = EthernetType(BigEndian.Uint16(packet[16:]))
		copy(packetId[:12], packet[:12])
		copy(packetId[12:], packet[16:])
	} else {
		copy(packetId[:], packet)
	}

	l4CsumOffset := 0
	if ethType == EthernetTypeIPv4 {
		id = uint64(BigEndian.Uint32(packetId[18:22])) | // IP ID, Frag
			(uint64(BigEndian.Uint16(packetId[24:26])) << 32) | // IP checksum
			(uint64(BigEndian.Uint16(packetId[16:18])) << 48) // IP total length
		ihl := int(packetId[14] & 0xF)
		ipProtocol := IPProtocol(packetId[23])
		if ipProtocol == IPProtocolUDP {
			l4CsumOffset = 14 + ihl*4 + 6
		} else if ipProtocol == IPProtocolTCP {
			l4CsumOffset = 14 + ihl*4 + 16
		}
	}

	if 0 < l4CsumOffset && l4CsumOffset < PACKET_ID_SIZE { // is L4 and valid offset; l4CsumOffset is even number
		*(*uint16)(unsafe.Pointer(&packetId[l4CsumOffset])) = 0 // ignore L4 checksum
	}

	return xxhash.Checksum32(packetId[:]), id, packetId
}

func Lookup(packet []byte, timestamp time.Duration) bool {
	hash, id, packetId := hashPacket(packet)
	return lookup(hash, id, timestamp, packetId)
}
