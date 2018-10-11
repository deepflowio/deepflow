package capture

import (
	"runtime"
	"sync"
	"time"

	. "github.com/google/gopacket/layers"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/dedup"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type Timestamp = time.Duration
type RawPacket = []byte
type PacketSize = int

type MetaPacketBlock = [1024]datatype.MetaPacket

type PacketHandler struct {
	sync.Pool

	block       *MetaPacketBlock
	blockCursor int

	ip    datatype.IPv4Int
	queue queue.MultiQueueWriter

	dedupTable *dedup.DedupTable
}

func (h *PacketHandler) preAlloc() *datatype.MetaPacket {
	metaPacket := &h.block[h.blockCursor]
	metaPacket.Exporter = h.ip
	return metaPacket
}

func (h *PacketHandler) confirmAlloc() {
	h.blockCursor++
	if h.blockCursor >= len(*h.block) {
		h.block = h.Get().(*MetaPacketBlock)
		h.blockCursor = 0
	}
}

func (h *PacketHandler) Handle(timestamp Timestamp, packet RawPacket, size PacketSize) {
	metaPacket := h.preAlloc()
	l2Len := metaPacket.ParseL2(packet)
	if metaPacket.Invalid {
		return
	}
	metaPacket.Timestamp = timestamp
	metaPacket.PacketLen = uint16(size)
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
			return
		}
	}
	if !metaPacket.Parse(packet[l2Len:]) {
		return
	}
	h.confirmAlloc()
	metaPacket.L2End0 = true // FIXME：需要根据RemoteSegments正确设置此值
	metaPacket.L2End1 = true
	h.queue.Put(queue.HashKey(metaPacket.GenerateHash()), metaPacket)
}

func (h *PacketHandler) Init(interfaceName string) {
	h.dedupTable = dedup.NewDedupTable(interfaceName)
	h.dedupTable.SetOverwriteTTL(true)
	gc := func(b *MetaPacketBlock) {
		*b = MetaPacketBlock{} // 重新初始化，避免无效的数据或不可预期的引用
		h.Put(b)
	}
	h.Pool.New = func() interface{} {
		block := new(MetaPacketBlock)
		runtime.SetFinalizer(block, gc)
		return block
	}
	h.block = new(MetaPacketBlock)
}
