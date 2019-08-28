package config

import (
	"gitlab.x.lan/yunshan/message/trident"
)

type Handler func(*trident.SyncResponse, *RpcInfoVersions)

type ConfigSynchronizer interface {
	Start()
	Stop()
	Register(Handler)
}
