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

package flow_metrics

import (
	_ "net/http/pprof"
	"strconv"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowio/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowio/deepflow/server/ingester/flow_metrics/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_metrics/dbwriter"
	"github.com/deepflowio/deepflow/server/ingester/flow_metrics/unmarshaller"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
	"github.com/deepflowio/deepflow/server/libs/grpc"
	libqueue "github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/receiver"
)

var log = logging.MustGetLogger("flow_metrics")

type FlowMetrics struct {
	unmarshallers []*unmarshaller.Unmarshaller
	platformDatas []*grpc.PlatformInfoTable
	dbwriters     []dbwriter.DbWriter
}

func NewFlowMetrics(cfg *config.Config, recv *receiver.Receiver, platformDataManager *grpc.PlatformDataManager) (*FlowMetrics, error) {
	flowMetrics := FlowMetrics{}

	manager := queue.NewManager(ingesterctl.INGESTERCTL_FLOW_METRICS_QUEUE)
	unmarshallQueueCount := int(cfg.UnmarshallQueueCount)
	unmarshallQueues := manager.NewQueuesUnmarshal(
		"1-recv-unmarshall", int(cfg.UnmarshallQueueSize), unmarshallQueueCount, 1,
		unmarshaller.DecodeForQueueMonitor,
		libqueue.OptionFlushIndicator(unmarshaller.FLUSH_INTERVAL*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))

	recv.RegistHandler(datatype.MESSAGE_TYPE_METRICS, unmarshallQueues, unmarshallQueueCount)

	var err error
	var writers []dbwriter.DbWriter
	ckWriter, err := dbwriter.NewCkDbWriter(cfg.Base.CKDB.ActualAddrs, cfg.Base.CKDBAuth.Username, cfg.Base.CKDBAuth.Password, cfg.Base.CKDB.ClusterName, cfg.Base.CKDB.StoragePolicy, cfg.Base.CKDB.TimeZone,
		cfg.CKWriterConfig, cfg.FlowMetricsTTL, cfg.Base.GetCKDBColdStorages())
	if err != nil {
		log.Error(err)
		return nil, err
	}
	writers = append(writers, ckWriter)

	if cfg.PromWriterConfig.Enabled {
		writer := dbwriter.NewPromWriter(cfg.PromWriterConfig)
		writers = append(writers, writer)
	}

	flowMetrics.dbwriters = writers
	flowMetrics.unmarshallers = make([]*unmarshaller.Unmarshaller, unmarshallQueueCount)
	flowMetrics.platformDatas = make([]*grpc.PlatformInfoTable, unmarshallQueueCount)
	for i := 0; i < unmarshallQueueCount; i++ {
		if i == 0 {
			// 只第一个上报数据节点信息
			flowMetrics.platformDatas[i], err = platformDataManager.NewPlatformInfoTable("ingester")
			debug.ServerRegisterSimple(ingesterctl.CMD_PLATFORMDATA_FLOW_METRIC, flowMetrics.platformDatas[i])
		} else {
			flowMetrics.platformDatas[i], err = platformDataManager.NewPlatformInfoTable("flowMetrics-" + strconv.Itoa(i))
		}
		if err != nil {
			return nil, err
		}
		flowMetrics.unmarshallers[i] = unmarshaller.NewUnmarshaller(i, flowMetrics.platformDatas[i], cfg.DisableSecondWrite, libqueue.QueueReader(unmarshallQueues.FixedMultiQueue[i]), flowMetrics.dbwriters)
	}

	return &flowMetrics, nil
}

func (r *FlowMetrics) Start() {
	for i := 0; i < len(r.unmarshallers); i++ {
		r.platformDatas[i].Start()
		go r.unmarshallers[i].QueueProcess()
	}
}

func (r *FlowMetrics) Close() error {
	for i := 0; i < len(r.unmarshallers); i++ {
		r.platformDatas[i].ClosePlatformInfoTable()
	}
	for i := 0; i < len(r.dbwriters); i++ {
		r.dbwriters[i].Close()
	}
	return nil
}
