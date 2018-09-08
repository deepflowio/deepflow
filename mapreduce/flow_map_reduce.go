package mapreduce

import (
	"gitlab.x.lan/application/droplet-app/pkg/mapper/flow"
	"gitlab.x.lan/platform/droplet-mapreduce/pkg/api"
	"gitlab.x.lan/platform/droplet-mapreduce/pkg/handler"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

func NewFlowMapProcess(zmqAppQueue queue.QueueWriter) *handler.FlowHandler {
	return handler.NewFlowHandler([]api.FlowProcessor{flow.NewProcessor()}, zmqAppQueue)
}
