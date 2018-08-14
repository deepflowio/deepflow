package config

import (
	"gitlab.x.lan/yunshan/droplet/protobuf"
)

type Handler func(*protobuf.SyncResponse)

type ConfigSynchronizer interface {
	Start()
	Stop()
	Register(Handler)
}
