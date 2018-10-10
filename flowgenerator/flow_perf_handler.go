package flowgenerator

import (
	. "gitlab.x.lan/yunshan/droplet-libs/datatype"
)

func (f *FlowGenerator) AcquireMetaFlowPerf() *MetaFlowPerf {
	return f.metaFlowPerfPool.Get().(*MetaFlowPerf)
}

func (f *FlowGenerator) ReleaseMetaFlowPerf(p *MetaFlowPerf) {
	p.resetMetaFlowPerf()
	f.metaFlowPerfPool.Put(p)
}

func (f *FlowGenerator) CloneMetaFlowPerf(p *MetaFlowPerf) *MetaFlowPerf {
	clone := f.AcquireMetaFlowPerf()
	*clone = *p
	return clone
}

func (f *FlowGenerator) initMetaFlowPerfPool() {
	f.metaFlowPerfPool.New = func() interface{} {
		return NewMetaFlowPerf(&f.perfCounter)
	}
}

func (f *FlowGenerator) checkIfDoFlowPerf(flowExtra *FlowExtra) bool {
	if flowExtra.taggedFlow.PolicyData == nil {
		return false
	}
	if flowExtra.taggedFlow.PolicyData.ActionFlags&
		(ACTION_TCP_FLOW_PERF_COUNTING|ACTION_TCP_FLOW_PERF_COUNT_BROKERING|
			ACTION_FLOW_STORING|ACTION_GEO_POSITIONING) > 0 {
		if flowExtra.metaFlowPerf == nil {
			flowExtra.metaFlowPerf = f.AcquireMetaFlowPerf()
		}
		return true
	}

	return false
}
