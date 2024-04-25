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

	"github.com/deepflowio/deepflow/server/ingester/app_log/config"
	baseconfig "github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_tag"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/datatype"
)

var log = logging.MustGetLogger("app_log.dbwriter")

const (
	LOG_DB    = "application_log"
	LOG_TABLE = "log"
)

type AppLogWriter struct {
	writerConfig baseconfig.CKWriterConfig

	ckWriter      *ckwriter.CKWriter
	flowTagWriter *flow_tag.FlowTagWriter
}

func (w *AppLogWriter) Write(l *ApplicationLogStore) {
	l.GenerateNewFlowTags(w.flowTagWriter.Cache)
	w.flowTagWriter.WriteFieldsAndFieldValuesInCache()
	w.ckWriter.Put(l)
}

func NewAppLogWriter(index int, msgType datatype.MessageType, config *config.Config, ckwriter *ckwriter.CKWriter) (*AppLogWriter, error) {
	w := &AppLogWriter{
		writerConfig: config.CKWriterConfig,
	}

	table := LOG_TABLE
	flowTagWriter, err := flow_tag.NewFlowTagWriter(index, table+"-"+msgType.String(), LOG_DB, config.TTL, ckdb.TimeFuncTwelveHour, config.Base, &w.writerConfig)
	if err != nil {
		return nil, err
	}

	w.flowTagWriter = flowTagWriter
	w.ckWriter = ckwriter
	return w, nil
}

func NewAppLogCKWriter(cfg *config.Config) (*ckwriter.CKWriter, error) {
	ckdbCfg := cfg.Base.CKDB
	ckTable := GenLogCKTable(ckdbCfg.ClusterName, ckdbCfg.StoragePolicy, LOG_TABLE, cfg.TTL, ckdb.GetColdStorage(cfg.Base.GetCKDBColdStorages(), LOG_DB, LOG_TABLE))
	return ckwriter.NewCKWriter(ckdbCfg.ActualAddrs, cfg.Base.CKDBAuth.Username, cfg.Base.CKDBAuth.Password,
		LOG_TABLE, cfg.Base.CKDB.TimeZone, ckTable, cfg.CKWriterConfig.QueueCount, cfg.CKWriterConfig.QueueSize, cfg.CKWriterConfig.BatchSize, cfg.CKWriterConfig.FlushTimeout, cfg.Base.CKDB.Watcher)
}
