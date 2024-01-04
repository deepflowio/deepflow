/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package prometheus

import (
	"strconv"
	"time"

	_ "golang.org/x/net/context"
	_ "google.golang.org/grpc"

	dropletqueue "github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/config"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/prometheus/decoder"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	libqueue "github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

type PrometheusHandler struct {
	Config               *config.Config
	LabelTable           *decoder.PrometheusLabelTable
	Decoders             []*decoder.Decoder
	SlowDecoders         []*decoder.SlowDecoder
	PlatformDatas        []*grpc.PlatformInfoTable
	prometheusLabelTable *decoder.PrometheusLabelTable
}

func NewPrometheusHandler(config *config.Config, recv *receiver.Receiver, platformDataManager *grpc.PlatformDataManager) (*PrometheusHandler, error) {
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_PROMETHEUS_QUEUE)
	queueCount := config.DecoderQueueCount
	msgType := datatype.MESSAGE_TYPE_PROMETHEUS
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+msgType.String(),
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))
	slowDecodeQueues := manager.NewQueues(
		"2-decode-to-slow-decode-"+msgType.String(),
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { decoder.ReleaseSlowItem(p.(*decoder.SlowItem)) }))

	recv.RegistHandler(msgType, decodeQueues, queueCount)

	prometheusLabelTable := decoder.NewPrometheusLabelTable(config.Base.ControllerIPs, int(config.Base.ControllerPort), config.LabelMsgMaxSize)

	prometheusLabelTable.RequestAllLabelIDs()
	currentColumnIndexMax := prometheusLabelTable.GetMaxAppLabelColumnIndex()
	initAppLabelColumnCount := config.AppLabelColumnMinCount
	if initAppLabelColumnCount < currentColumnIndexMax {
		initAppLabelColumnCount = currentColumnIndexMax
	}

	decoders := make([]*decoder.Decoder, queueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	slowDecoders := make([]*decoder.SlowDecoder, queueCount)
	slowPlatformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	for i := 0; i < queueCount; i++ {
		var err error
		platformDatas[i], err = platformDataManager.NewPlatformInfoTable(msgType.String() + "-" + strconv.Itoa(i))
		if i == 0 {
			debug.ServerRegisterSimple(ingesterctl.CMD_PLATFORMDATA_PROMETHEUS, platformDatas[i])
		}
		if err != nil {
			return nil, err
		}
		metricsWriter, err := dbwriter.NewPrometheusWriter(i, initAppLabelColumnCount, msgType.String(), dbwriter.PROMETHEUS_DB, config)
		if err != nil {
			return nil, err
		}
		decoders[i] = decoder.NewDecoder(
			i,
			platformDatas[i],
			prometheusLabelTable,
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			queue.QueueWriter(slowDecodeQueues.FixedMultiQueue[i]),
			metricsWriter,
			config,
		)
		slowMetricsWriter, err := dbwriter.NewPrometheusWriter(i, initAppLabelColumnCount, "slow-prometheus", dbwriter.PROMETHEUS_DB, config)
		if err != nil {
			return nil, err
		}
		slowPlatformDatas[i], err = platformDataManager.NewPlatformInfoTable("slow-prometheus-" + strconv.Itoa(i))
		slowDecoders[i] = decoder.NewSlowDecoder(
			i,
			slowPlatformDatas[i],
			prometheusLabelTable,
			queue.QueueReader(slowDecodeQueues.FixedMultiQueue[i]),
			slowMetricsWriter,
			config,
		)
	}
	return &PrometheusHandler{
		Config:               config,
		Decoders:             decoders,
		PlatformDatas:        platformDatas,
		prometheusLabelTable: prometheusLabelTable,
		SlowDecoders:         slowDecoders,
	}, nil
}

func (m *PrometheusHandler) Start() {
	for _, platformData := range m.PlatformDatas {
		platformData.Start()
	}

	for i, decoder := range m.Decoders {
		go decoder.Run()
		go m.SlowDecoders[i].Run()
	}
}

func (m *PrometheusHandler) Close() error {
	for _, platformData := range m.PlatformDatas {
		platformData.ClosePlatformInfoTable()
	}
	return nil
}
