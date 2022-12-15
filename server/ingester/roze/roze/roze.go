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

package roze

import (
	_ "net/http/pprof"
	"strconv"
	"time"

	logging "github.com/op/go-logging"

	"github.com/deepflowys/deepflow/server/ingester/droplet/queue"
	"github.com/deepflowys/deepflow/server/ingester/ingesterctl"
	"github.com/deepflowys/deepflow/server/ingester/roze/config"
	"github.com/deepflowys/deepflow/server/ingester/roze/dbwriter"
	"github.com/deepflowys/deepflow/server/ingester/roze/unmarshaller"
	"github.com/deepflowys/deepflow/server/libs/datatype"
	"github.com/deepflowys/deepflow/server/libs/debug"
	"github.com/deepflowys/deepflow/server/libs/grpc"
	libqueue "github.com/deepflowys/deepflow/server/libs/queue"
	"github.com/deepflowys/deepflow/server/libs/receiver"
)

const (
	CMD_PLATFORMDATA = 33
)

var log = logging.MustGetLogger("roze")

type Roze struct {
	unmarshallers []*unmarshaller.Unmarshaller
	platformDatas []*grpc.PlatformInfoTable
	dbwriter      *dbwriter.DbWriter
}

func NewRoze(cfg *config.Config, recv *receiver.Receiver, platformDataManager *grpc.PlatformDataManager) (*Roze, error) {
	roze := Roze{}
	manager := queue.NewManager(ingesterctl.INGESTERCTL_ROZE_QUEUE)
	unmarshallQueueCount := int(cfg.UnmarshallQueueCount)
	unmarshallQueues := manager.NewQueuesUnmarshal(
		"1-recv-unmarshall", int(cfg.UnmarshallQueueSize), unmarshallQueueCount, 1,
		unmarshaller.DecodeForQueueMonitor,
		libqueue.OptionFlushIndicator(unmarshaller.FLUSH_INTERVAL*time.Second),
		libqueue.OptionRelease(func(p interface{}) { receiver.ReleaseRecvBuffer(p.(*receiver.RecvBuffer)) }))

	recv.RegistHandler(datatype.MESSAGE_TYPE_METRICS, unmarshallQueues, unmarshallQueueCount)

	var err error
	roze.dbwriter, err = dbwriter.NewDbWriter(cfg.Base.CKDB.ActualAddr, cfg.Base.CKDBAuth.Username, cfg.Base.CKDBAuth.Password, cfg.Base.CKDB.ClusterName, cfg.Base.CKDB.StoragePolicy,
		cfg.CKWriterConfig, cfg.FlowMetricsTTL, cfg.Base.GetCKDBColdStorages())
	if err != nil {
		log.Error(err)
		return nil, err
	}

	roze.unmarshallers = make([]*unmarshaller.Unmarshaller, unmarshallQueueCount)
	roze.platformDatas = make([]*grpc.PlatformInfoTable, unmarshallQueueCount)
	for i := 0; i < unmarshallQueueCount; i++ {
		if i == 0 {
			// 只第一个上报数据节点信息
			roze.platformDatas[i], err = platformDataManager.NewPlatformInfoTable(true, "roze")
			debug.ServerRegisterSimple(CMD_PLATFORMDATA, roze.platformDatas[i])
		} else {
			roze.platformDatas[i], err = platformDataManager.NewPlatformInfoTable(false, "roze-"+strconv.Itoa(i))
		}
		if err != nil {
			return nil, err
		}
		roze.unmarshallers[i] = unmarshaller.NewUnmarshaller(i, roze.platformDatas[i], cfg.DisableSecondWrite, libqueue.QueueReader(unmarshallQueues.FixedMultiQueue[i]), roze.dbwriter)
	}

	return &roze, nil
}

func (r *Roze) Start() {
	for i := 0; i < len(r.unmarshallers); i++ {
		r.platformDatas[i].Start()
		go r.unmarshallers[i].QueueProcess()
	}
}

func (r *Roze) Close() error {
	for i := 0; i < len(r.unmarshallers); i++ {
		r.platformDatas[i].ClosePlatformInfoTable()
	}
	r.dbwriter.Close()
	return nil
}
