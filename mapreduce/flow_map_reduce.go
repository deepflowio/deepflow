package mapreduce

import (
	epc "gitlab.x.lan/application/droplet-app/pkg/flow/epc_flow_topo"
	"gitlab.x.lan/platform/droplet-mapreduce/pkg/api"
	"gitlab.x.lan/platform/droplet-mapreduce/pkg/handler"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
)

func NewFlowMapProcess(zmqFlowQueue queue.QueueWriter, zmqAppQueue queue.QueueWriter) *handler.FlowHandler {
	return handler.NewFlowHandler([]api.FlowProcessor{epc.NewProcessor()}, zmqFlowQueue, zmqAppQueue)
}
