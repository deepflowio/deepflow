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
	if p != nil {
		p.resetMetaFlowPerf()
		metaFlowPerfPool.Put(p)
	}
}

var seqSegmentSlicePool = pool.NewLockFreePool(func() interface{} {
	return make([]SeqSegment, 0, SEQ_LIST_MAX_LEN+1)
})

func AcquireSeqSegmentSlice() []SeqSegment {
	return seqSegmentSlicePool.Get().([]SeqSegment)
}

func ReleaseSeqSegmentSlice(p []SeqSegment) {
	if p != nil {
		p = p[:0]
		seqSegmentSlicePool.Put(p)
	}
}
