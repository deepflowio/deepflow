package mapreduce

import (
	isp "gitlab.x.lan/application/droplet-app/pkg/metering/bw_usage_isp_usage"
	"gitlab.x.lan/platform/droplet-mapreduce/pkg/api"
	"gitlab.x.lan/platform/droplet-mapreduce/pkg/handler"
)

func NewMeteringMapProcess() *handler.MeteringHandler {
	return handler.NewMeteringHandler([]api.MeteringProcessor{isp.NewProcessor()})
}
