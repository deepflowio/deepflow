/*
 * Copyright (c) 2022 Yunshan Networks
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

const (
	CMD_PLATFORMDATA = 33
)

var log = logging.MustGetLogger("flow_metrics")

type FlowMetrics struct {
	unmarshallers []*unmarshaller.Unmarshaller
	platformDatas []*grpc.PlatformInfoTable
	dbwriter      *dbwriter.DbWriter
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
	flowMetrics.dbwriter, err = dbwriter.NewDbWriter(cfg.Base.CKDB.ActualAddrs, cfg.Base.CKDBAuth.Username, cfg.Base.CKDBAuth.Password, cfg.Base.CKDB.ClusterName, cfg.Base.CKDB.StoragePolicy,
		cfg.CKWriterConfig, cfg.FlowMetricsTTL, cfg.Base.GetCKDBColdStorages())
	if err != nil {
		log.Error(err)
		return nil, err
	}

	flowMetrics.unmarshallers = make([]*unmarshaller.Unmarshaller, unmarshallQueueCount)
	flowMetrics.platformDatas = make([]*grpc.PlatformInfoTable, unmarshallQueueCount)
	for i := 0; i < unmarshallQueueCount; i++ {
		if i == 0 {
			// 只第一个上报数据节点信息
			flowMetrics.platformDatas[i], err = platformDataManager.NewPlatformInfoTable(true, "roze")
			debug.ServerRegisterSimple(CMD_PLATFORMDATA, flowMetrics.platformDatas[i])
		} else {
			flowMetrics.platformDatas[i], err = platformDataManager.NewPlatformInfoTable(false, "flowMetrics-"+strconv.Itoa(i))
		}
		if err != nil {
			return nil, err
		}
		flowMetrics.unmarshallers[i] = unmarshaller.NewUnmarshaller(i, flowMetrics.platformDatas[i], cfg.DisableSecondWrite, libqueue.QueueReader(unmarshallQueues.FixedMultiQueue[i]), flowMetrics.dbwriter)
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
	r.dbwriter.Close()
	return nil
}
