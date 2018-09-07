package capture

import (
	"runtime"
	"sync"
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/dedup"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type Timestamp = time.Duration
type RawPacket = []byte

type PacketHandler interface {
	Handle(Timestamp, RawPacket)
}

type DataHandler struct {
	sync.Pool

	gc    func(p *datatype.MetaPacket)
	ip    datatype.IPv4Int
	queue queue.QueueWriter
}

func (h *DataHandler) Handle(timestamp Timestamp, packet RawPacket) {
	metaPacket := h.Get().(*datatype.MetaPacket)
	*metaPacket = datatype.MetaPacket{
		Timestamp: timestamp,
		InPort:    uint32(datatype.PACKET_SOURCE_ISP),
		Exporter:  h.ip,
		PacketLen: uint16(len(packet)),
	}
	if !metaPacket.Parse(packet) {
		h.Put(metaPacket)
		return
	}
	runtime.SetFinalizer(metaPacket, h.gc)
	h.queue.Put(metaPacket)
}

type TapHandler DataHandler

func (h *TapHandler) Handle(timestamp Timestamp, packet RawPacket) {
	metaPacket := &datatype.MetaPacket{
		Timestamp: timestamp,
		InPort:    uint32(datatype.PACKET_SOURCE_TOR),
		Exporter:  h.ip,
		PacketLen: uint16(len(packet)),
	}
	tunnel := datatype.TunnelInfo{}
	if offset := tunnel.Decapsulate(packet); offset > 0 {
		packet = packet[offset:]
		metaPacket.Tunnel = &tunnel
	}
	if dedup.Lookup(packet, timestamp) {
		h.Put(metaPacket)
		return
	}
	if !metaPacket.Parse(packet) {
		h.Put(metaPacket)
		return
	}
	runtime.SetFinalizer(metaPacket, h.gc)
	h.queue.Put(metaPacket)
}

func (h *TapHandler) Init() *TapHandler {
	h.Pool.New = func() interface{} {
		return new(datatype.MetaPacket)
	}
	h.gc = func(p *datatype.MetaPacket) { h.Put(p) }
	return h
}
