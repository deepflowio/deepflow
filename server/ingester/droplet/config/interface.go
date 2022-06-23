package config

import (
	"github.com/metaflowys/metaflow/message/trident"
)

type Handler func(*trident.SyncResponse, *RpcInfoVersions)

type ConfigSynchronizer interface {
	Start()
	Stop()
	Register(Handler)
}
