/*
 * Copyright (c) 2023 Yunshan Networks
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

package ext_metrics

import (
	"strconv"
	"time"

	_ "golang.org/x/net/context"
	_ "google.golang.org/grpc"

	dropletqueue "github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/ext_metrics/config"
	"github.com/deepflowio/deepflow/server/ingester/ext_metrics/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/ext_metrics/decoder"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	"github.com/deepflowio/deepflow/server/libs/queue"
	libqueue "github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

const (
	CMD_PLATFORMDATA_EXT_METRICS = 35
)

type ExtMetrics struct {
	Config        *config.Config
	Telegraf      *Metricsor
	MetaflowStats *Metricsor
}

type Metricsor struct {
	Config              *config.Config
	Decoders            []*decoder.Decoder
	PlatformDataEnabled bool
	PlatformDatas       []*grpc.PlatformInfoTable
	Writer              *dbwriter.ExtMetricsWriter
}

func NewExtMetrics(config *config.Config, recv *receiver.Receiver, platformDataManager *grpc.PlatformDataManager) (*ExtMetrics, error) {
	manager := dropletqueue.NewManager(ingesterctl.INGESTERCTL_EXTMETRICS_QUEUE)

	telegraf, err := NewMetricsor(datatype.MESSAGE_TYPE_TELEGRAF, dbwriter.EXT_METRICS_DB, config, platformDataManager, manager, recv, true)
	if err != nil {
		return nil, err
	}
	deepflowStats, err := NewMetricsor(datatype.MESSAGE_TYPE_DFSTATS, dbwriter.DEEPFLOW_SYSTEM_DB, config, platformDataManager, manager, recv, false)
	if err != nil {
		return nil, err
	}
	return &ExtMetrics{
		Config:        config,
		Telegraf:      telegraf,
		MetaflowStats: deepflowStats,
	}, nil
}

func NewMetricsor(msgType datatype.MessageType, db string, config *config.Config, platformDataManager *grpc.PlatformDataManager, manager *dropletqueue.Manager, recv *receiver.Receiver, platformDataEnabled bool) (*Metricsor, error) {
	queueCount := config.DecoderQueueCount
	decodeQueues := manager.NewQueues(
		"1-receive-to-decode-"+msgType.String(),
		config.DecoderQueueSize,
		queueCount,
		1,
		libqueue.OptionFlushIndicator(3*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))
	recv.RegistHandler(msgType, decodeQueues, queueCount)

	decoders := make([]*decoder.Decoder, queueCount)
	platformDatas := make([]*grpc.PlatformInfoTable, queueCount)
	for i := 0; i < queueCount; i++ {
		if platformDataEnabled {
			var err error
			platformDatas[i], err = platformDataManager.NewPlatformInfoTable("ext-metrics-" + msgType.String() + "-" + strconv.Itoa(i))
			if i == 0 {
				debug.ServerRegisterSimple(CMD_PLATFORMDATA_EXT_METRICS, platformDatas[i])
			}
			if err != nil {
				return nil, err
			}
		}
		metricsWriter, err := dbwriter.NewExtMetricsWriter(i, msgType, db, config)
		if err != nil {
			return nil, err
		}
		decoders[i] = decoder.NewDecoder(
			i,
			msgType,
			platformDatas[i],
			queue.QueueReader(decodeQueues.FixedMultiQueue[i]),
			metricsWriter,
			config,
		)
	}
	return &Metricsor{
		Config:              config,
		Decoders:            decoders,
		PlatformDataEnabled: platformDataEnabled,
		PlatformDatas:       platformDatas,
	}, nil
}

func (m *Metricsor) Start() {
	if m.PlatformDataEnabled {
		for _, platformData := range m.PlatformDatas {
			platformData.Start()
		}
	}

	for _, decoder := range m.Decoders {
		go decoder.Run()
	}
}

func (m *Metricsor) Close() {
	for _, platformData := range m.PlatformDatas {
		if m.PlatformDataEnabled {
			platformData.ClosePlatformInfoTable()
		}
	}
}

func (s *ExtMetrics) Start() {
	s.Telegraf.Start()
	s.MetaflowStats.Start()
}

func (s *ExtMetrics) Close() error {
	s.Telegraf.Close()
	s.MetaflowStats.Close()
	return nil
}
