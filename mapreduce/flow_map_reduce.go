package mapreduce

import (
	epc "gitlab.x.lan/application/droplet-app/pkg/flow/epc_flow_topo"
	"gitlab.x.lan/platform/droplet-mapreduce"
	"gitlab.x.lan/platform/droplet-mapreduce/pkg/api"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

type MapProcessor struct {
	queue.OverwriteQueue
}

func (m *MapProcessor) FlowProcessor() {

	taggedFlow := m.Get().(*datatype.TaggedFlow)
	m.FlowHandler(taggedFlow)
}

func (m *MapProcessor) FlowHandler(flow *datatype.TaggedFlow) []string {
	var processors []api.FlowProcessor
	processor := epc.NewProcessor()
	processors = append(processors, processor)
	flowHandler := droplet_mapreduce.NewFlowHandler(processors)
	flowHandler.Process(*flow)
	var a []string
	for i := 0; i < flowHandler.NumberOfApps; i++ {
		a = flowHandler.Stats[0][i].KeySet()
	}
	return a
}
