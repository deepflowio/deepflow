package platformdata

import (
	"net"

	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/grpc"
	"gitlab.x.lan/yunshan/droplet-libs/receiver"
)

var PlatformData *grpc.PlatformInfoTable

const (
	CMD_PLATFORMDATA = 33
)

func New(ips []net.IP, port int, processName string, shardID uint32, replicaIP string, receiver *receiver.Receiver) {
	PlatformData = grpc.NewPlatformInfoTable(ips, port, processName, shardID, replicaIP, receiver)
	debug.ServerRegisterSimple(CMD_PLATFORMDATA, PlatformData)
}

func Start() {
	PlatformData.Start()
}

func Close() {
	PlatformData.Close()
}
