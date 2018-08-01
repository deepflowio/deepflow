package handler

import (
	"net"
)

type PacketHandler interface {
	Handle([]byte, *MetaPacket) bool
	Close()
}

type PacketHandlerManager interface {
	Allocate(net.HardwareAddr, net.Interface) PacketHandler
	Release(PacketHandler)
	Close()
}
