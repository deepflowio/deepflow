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

package dbwriter

import (
	logging "github.com/op/go-logging"

	"github.com/deepflowys/deepflow/server/ingester/config"
	"github.com/deepflowys/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowys/deepflow/server/ingester/stream/common"
	"github.com/deepflowys/deepflow/server/ingester/stream/jsonify"
	"github.com/deepflowys/deepflow/server/libs/ckdb"
)

var log = logging.MustGetLogger("stream.dbwriter")

const (
	CACHE_SIZE       = 10240
	DefaultDayForTTL = 3
	DefaultPartition = ckdb.TimeFuncHour
)

type FlowLogWriter struct {
	ckwriters []*ckwriter.CKWriter
}

func newFlowLogTable(id common.FlowLogID, columns []*ckdb.Column, engine ckdb.EngineType) *ckdb.Table {
	var orderKeys = []string{}
	if id == common.L7_FLOW_ID {
		orderKeys = []string{"l7_protocol"}
	}
	orderKeys = append(orderKeys, "l3_epc_id_1", "ip4_1", "ip6_1", "l3_epc_id_0", "ip4_0", "ip6_0", "server_port")

	return &ckdb.Table{
		ID:              uint8(id),
		Database:        common.FLOW_LOG_DB,
		LocalName:       id.String() + "_local",
		GlobalName:      id.String(),
		Columns:         columns,
		TimeKey:         id.TimeKey(),
		Engine:          engine,
		PartitionFunc:   DefaultPartition,
		TTL:             DefaultDayForTTL,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

func GetFlowLogTables(engine ckdb.EngineType) []*ckdb.Table {
	return []*ckdb.Table{
		newFlowLogTable(common.L4_FLOW_ID, jsonify.FlowLoggerColumns(), engine),
		newFlowLogTable(common.L7_FLOW_ID, jsonify.L7LoggerColumns(), engine),
	}
}

func NewFlowLogWriter(primaryAddr, secondaryAddr, user, password string, replicaEnabled bool, ckWriterCfg config.CKWriterConfig) (*FlowLogWriter, error) {
	ckwriters := make([]*ckwriter.CKWriter, common.FLOWLOG_ID_MAX)
	var err error
	var tables []*ckdb.Table
	if replicaEnabled {
		tables = GetFlowLogTables(ckdb.ReplicatedMergeTree)
	} else {
		tables = GetFlowLogTables(ckdb.MergeTree)
	}
	for i, table := range tables {
		counterName := common.FlowLogID(table.ID).String()
		ckwriters[i], err = ckwriter.NewCKWriter(primaryAddr, secondaryAddr, user, password, counterName, table, replicaEnabled,
			ckWriterCfg.QueueCount, ckWriterCfg.QueueSize, ckWriterCfg.BatchSize, ckWriterCfg.FlushTimeout)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		ckwriters[i].Run()
	}

	return &FlowLogWriter{
		ckwriters: ckwriters,
	}, nil
}

func (w *FlowLogWriter) Put(index int, items ...interface{}) {
	w.ckwriters[index].Put(items...)
}

func (w *FlowLogWriter) Close() {
	for _, ckwriter := range w.ckwriters {
		ckwriter.Close()
	}
}
