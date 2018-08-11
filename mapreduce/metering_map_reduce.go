package mapreduce

import (
	isp "gitlab.x.lan/application/droplet-app/pkg/metering/bw_usage_isp_usage"
	"gitlab.x.lan/platform/droplet-mapreduce"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/queue"

	"gitlab.x.lan/platform/droplet-mapreduce/pkg/api"
)

type MeteringMapProcessor struct {
	queue.OverwriteQueue
}

func (m *MeteringMapProcessor) FlowProcessor() {
	taggedMetering := m.Get().(*datatype.TaggedMetering)
	m.MeteringHandler(taggedMetering)
}

func (m *MeteringMapProcessor) MeteringHandler(metering *datatype.TaggedMetering) []string {
	var processors []api.MeteringProcessor
	processor := isp.NewProcessor()
	processors = append(processors, processor)
	meteringHandler := droplet_mapreduce.NewMeteringHandler(processors)
	meteringHandler.Process(*metering)
	var a []string
	for i := 0; i < meteringHandler.NumberOfApps; i++ {
		a = meteringHandler.Stats[0][i].KeySet()
	}
	return a
}
