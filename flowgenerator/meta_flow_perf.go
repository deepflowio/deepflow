package flowgenerator

import (
	"sync"
)

var metaFlowPerfPool = sync.Pool{
	New: func() interface{} { return new(MetaFlowPerf) },
}

func AcquireMetaFlowPerf() *MetaFlowPerf {
	ReleaseMetaFlowPerf(&MetaFlowPerf{})
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
