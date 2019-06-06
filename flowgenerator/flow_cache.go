package flowgenerator

import (
	"sync"

	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

type FlowCache struct {
	sync.Mutex

	capacity int
	flowList *ListFlowExtra
}

type FlowCacheHashMap struct {
	hashMap             []*FlowCache
	hashBasis           uint32
	mapSize             uint64
	timeoutCleanerCount uint64
	innerTunnelInfo     *TunnelInfo
}
