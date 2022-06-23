package config

import (
	"gitlab.yunshan.net/yunshan/message/trident"
)

type Handler func(*trident.SyncResponse, *RpcInfoVersions)

type ConfigSynchronizer interface {
	Start()
	Stop()
	Register(Handler)
}
