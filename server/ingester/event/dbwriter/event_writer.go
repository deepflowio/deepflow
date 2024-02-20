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

package dbwriter

import (
	logging "github.com/op/go-logging"

	baseconfig "github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_tag"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype"
)

var log = logging.MustGetLogger("event.dbwriter")

const (
	EVENT_DB = "event"
)

type ClusterNode struct {
	Addr string
	Port uint16
}

type tableInfo struct {
	tableName string
	ckwriter  *ckwriter.CKWriter
}

type EventWriter struct {
	msgType           datatype.MessageType
	ckdbAddrs         []string
	ckdbUsername      string
	ckdbPassword      string
	ckdbCluster       string
	ckdbStoragePolicy string
	ckdbColdStorages  map[string]*ckdb.ColdStorage
	ttl               int
	writerConfig      baseconfig.CKWriterConfig

	ckWriter      *ckwriter.CKWriter
	flowTagWriter *flow_tag.FlowTagWriter
}

func (w *EventWriter) Write(e *EventStore) {
	e.GenerateNewFlowTags(w.flowTagWriter.Cache)
	w.flowTagWriter.WriteFieldsAndFieldValuesInCache()
	w.ckWriter.Put(e)
}

func (w *EventWriter) WriteAlarmEvent(e *AlarmEventStore) {
	w.ckWriter.Put(e)
}

func NewEventWriter(table string, decoderIndex int, config *config.Config) (*EventWriter, error) {
	w := &EventWriter{
		ckdbAddrs:         config.Base.CKDB.ActualAddrs,
		ckdbUsername:      config.Base.CKDBAuth.Username,
		ckdbPassword:      config.Base.CKDBAuth.Password,
		ckdbCluster:       config.Base.CKDB.ClusterName,
		ckdbStoragePolicy: config.Base.CKDB.StoragePolicy,
		ckdbColdStorages:  config.Base.GetCKDBColdStorages(),
	}
	if table == common.RESOURCE_EVENT.TableName() {
		w.ttl = config.TTL
		w.writerConfig = config.CKWriterConfig
	} else {
		w.ttl = config.PerfTTL
		w.writerConfig = config.PerfCKWriterConfig
	}
	flowTagWriter, err := flow_tag.NewFlowTagWriter(decoderIndex, table, EVENT_DB, w.ttl, ckdb.TimeFuncTwelveHour, config.Base, &w.writerConfig)
	if err != nil {
		return nil, err
	}
	w.flowTagWriter = flowTagWriter

	ckTable := GenEventCKTable(w.ckdbCluster, w.ckdbStoragePolicy, table, w.ttl, ckdb.GetColdStorage(w.ckdbColdStorages, EVENT_DB, table))

	ckwriter, err := ckwriter.NewCKWriter(w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
		table, config.Base.CKDB.TimeZone, ckTable, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout)
	if err != nil {
		return nil, err
	}
	w.ckWriter = ckwriter
	w.ckWriter.Run()
	return w, nil
}
