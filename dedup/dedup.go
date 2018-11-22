package dedup

import (
	. "encoding/binary"
	"time"

	"github.com/OneOfOne/xxhash"
	. "github.com/google/gopacket/layers"
	"github.com/op/go-logging"

	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

var log = logging.MustGetLogger("dedup")

func (t *DedupTable) hashPacket(packet []byte) (uint32, uint64, PacketId) {
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

	if ethType == EthernetTypeIPv4 {
		if t.ignoreTTL {
			packetId[22] = 128
		}
		id = uint64(BigEndian.Uint32(packetId[18:22])) | // IP ID, Frag
			(uint64(BigEndian.Uint16(packetId[24:26])) << 32) | // IP checksum
			(uint64(BigEndian.Uint16(packetId[16:18])) << 48) // IP total length
		ihl := int(packetId[14] & 0xF)
		ipProtocol := IPProtocol(packetId[23])
		if ipProtocol == IPProtocolUDP {
			BigEndian.PutUint16(packetId[14+ihl*4+6:], 0) // ignore L4 checksum
		} else if ipProtocol == IPProtocolTCP {
			BigEndian.PutUint16(packetId[14+ihl*4+16:], 0) // ignore L4 checksum
		}
	}

	return xxhash.Checksum32(packetId[:]), id, packetId
}

func (t *DedupTable) IsDuplicate(packet []byte, timestamp time.Duration) bool {
	hash, id, packetId := t.hashPacket(packet)
	return t.lookup(hash, id, timestamp, packetId)
}

func NewDedupTable(name string) *DedupTable {
	t := &DedupTable{
		hashTable: &HashTable{},
		queue:     &List{},
		buffer:    &List{},
		counter:   &Counter{},
	}
	for i := 0; i < HASH_TABLE_SIZE; i++ {
		t.hashTable[i] = &List{}
	}
	stats.RegisterCountable("dedup", t, stats.OptionStatTags{"name": name})
	return t
}
