package mapreduce

import (
	"gitlab.x.lan/application/droplet-app/pkg/mapper/flow"
	"gitlab.x.lan/application/droplet-app/pkg/mapper/geo"
	"gitlab.x.lan/application/droplet-app/pkg/mapper/perf"
	"gitlab.x.lan/platform/droplet-mapreduce/pkg/api"
	"gitlab.x.lan/platform/droplet-mapreduce/pkg/handler"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

const GEO_FILE_LOCATION = "/usr/share/droplet/ip_info_mini.json"

func NewFlowMapProcess(zmqAppQueue queue.QueueWriter) *handler.FlowHandler {
	return handler.NewFlowHandler([]api.FlowProcessor{
		flow.NewProcessor(),
		perf.NewProcessor(),
		geo.NewProcessor(GEO_FILE_LOCATION),
	}, zmqAppQueue)
}
