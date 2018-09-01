package capture

import (
	"time"

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"

	"gitlab.x.lan/yunshan/droplet/dedup"
)

type Timestamp = time.Duration
type RawPacket = []byte

type PacketHandler interface {
	Handle(Timestamp, RawPacket)
}

type DataHandler struct {
	ip    datatype.IPv4Int
	queue queue.QueueWriter
}

func (h *DataHandler) Handle(timestamp Timestamp, packet RawPacket) {
	metaPacket := &datatype.MetaPacket{
		Timestamp: timestamp,
		InPort:    uint32(datatype.PACKET_SOURCE_ISP),
		Exporter:  h.ip,
		PacketLen: uint16(len(packet)),
	}
	if !metaPacket.Parse(packet) {
		return
	}
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
		return
	}
	if !metaPacket.Parse(packet) {
		return
	}
	h.queue.Put(metaPacket)
}
