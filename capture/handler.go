package capture

import (
	"time"

	. "github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/dedup"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type Timestamp = time.Duration
type RawPacket = []byte
type PacketSize = int

const BATCH_SIZE = 1024

type PacketHandler struct {
	ip             datatype.IPv4Int
	queue          queue.MultiQueueWriter
	remoteSegments *SegmentSet
	defaultTapType uint32
	keys           [BATCH_SIZE + 1]queue.HashKey
	metaPackets    []interface{}

	dedupTable *dedup.DedupTable
}

func (h *PacketHandler) Handle(timestamp Timestamp, packet RawPacket, size PacketSize) {
	metaPacket := datatype.AcquireMetaPacket()
	l2Len := metaPacket.ParseL2(packet)
	if metaPacket.Invalid {
		datatype.ReleaseMetaPacket(metaPacket)
		return
	}
	metaPacket.Exporter = h.ip
	metaPacket.Timestamp = timestamp
	metaPacket.PacketLen = uint16(size)
	if metaPacket.InPort == 0 {
		metaPacket.InPort = h.defaultTapType
	}
	if (metaPacket.InPort & datatype.PACKET_SOURCE_TOR) == datatype.PACKET_SOURCE_TOR {
		if metaPacket.EthType == EthernetTypeIPv4 {
			tunnel := datatype.TunnelInfo{}
			if offset := tunnel.Decapsulate(packet[l2Len:]); offset > 0 {
				metaPacket.Tunnel = &tunnel
				packet = packet[l2Len+offset:]
				l2Len = metaPacket.ParseL2(packet)
			}
		}
		if h.dedupTable.IsDuplicate(packet, timestamp) {
			datatype.ReleaseMetaPacket(metaPacket)
			return
		}
	}
	if !metaPacket.Parse(packet[l2Len:]) {
		datatype.ReleaseMetaPacket(metaPacket)
		return
	}
	metaPacket.L2End0 = !h.remoteSegments.Lookup(metaPacket.MacSrc)
	metaPacket.L2End1 = !h.remoteSegments.Lookup(metaPacket.MacDst)

	h.metaPackets = append(h.metaPackets, metaPacket)
	if len(h.metaPackets) >= cap(h.metaPackets) {
		h.Flush()
	}
}

func (h *PacketHandler) Flush() {
	if len(h.metaPackets) > 0 {
		keys := h.keys[1:]
		for i, metaPacket := range h.metaPackets {
			keys[i] = queue.HashKey(metaPacket.(*datatype.MetaPacket).GenerateHash())
		}
		h.queue.Puts(h.keys[:len(h.metaPackets)+1], h.metaPackets)
		h.metaPackets = h.metaPackets[:0]
	}
}

func (h *PacketHandler) Init(interfaceName string) {
	h.dedupTable = dedup.NewDedupTable(interfaceName)
	h.dedupTable.SetOverwriteTTL(true)
	// FIXME: 因为queue的实现和interface的调用约定不一致，
	// 因此存在产生BUG的风险，需要尽快修改
	h.keys[0] = queue.HashKey(1)
	h.metaPackets = make([]interface{}, 0, BATCH_SIZE)
}
