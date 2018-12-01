package flowgenerator

import (
	"gitlab.x.lan/yunshan/droplet-libs/pool"
)

var metaFlowPerfPool = pool.NewLockFreePool(func() interface{} {
	return new(MetaFlowPerf)
})

func AcquireMetaFlowPerf() *MetaFlowPerf {
	return metaFlowPerfPool.Get().(*MetaFlowPerf)
}

func ReleaseMetaFlowPerf(p *MetaFlowPerf) {
	p.resetMetaFlowPerf()
	metaFlowPerfPool.Put(p)
}

func CloneMetaFlowPerf(p *MetaFlowPerf) *MetaFlowPerf {
	clone := AcquireMetaFlowPerf()
	*clone = *p
	return clone
}
