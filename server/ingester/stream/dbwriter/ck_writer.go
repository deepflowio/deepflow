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

	basecommon "github.com/deepflowys/deepflow/server/ingester/common"
	"github.com/deepflowys/deepflow/server/ingester/config"
	"github.com/deepflowys/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowys/deepflow/server/ingester/stream/common"
	streamconfig "github.com/deepflowys/deepflow/server/ingester/stream/config"
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

func newFlowLogTable(id common.FlowLogID, columns []*ckdb.Column, engine ckdb.EngineType, cluster, storagePolicy string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	var orderKeys = []string{}
	flowKeys := []string{"l3_epc_id_1", "ip4_1", "ip6_1", "l3_epc_id_0", "ip4_0", "ip6_0", "server_port"}
	switch id {
	case common.L7_FLOW_ID:
		orderKeys = []string{"l7_protocol"}
		orderKeys = append(orderKeys, flowKeys...)
	case common.L4_FLOW_ID, common.L4_PCAP_FLOW_ID:
		orderKeys = flowKeys
	case common.L4_PACKET_ID:
		orderKeys = []string{"flow_id", "vtap_id"}
	default:
		panic("unreachalable")
	}

	return &ckdb.Table{
		Version:         basecommon.CK_VERSION,
		ID:              uint8(id),
		Database:        common.FLOW_LOG_DB,
		LocalName:       id.String() + "_local",
		GlobalName:      id.String(),
		Columns:         columns,
		TimeKey:         id.TimeKey(),
		Engine:          engine,
		Cluster:         cluster,
		StoragePolicy:   storagePolicy,
		PartitionFunc:   DefaultPartition,
		TTL:             ttl,
		ColdStorage:     *coldStorage,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

func GetFlowLogTables(engine ckdb.EngineType, cluster, storagePolicy string, l4LogTtl, l7LogTtl, l4PacketTtl int, coldStorages map[string]*ckdb.ColdStorage) []*ckdb.Table {
	return []*ckdb.Table{
		newFlowLogTable(common.L4_FLOW_ID, jsonify.L4FlowLogColumns(), engine, cluster, storagePolicy, l4LogTtl, ckdb.GetColdStorage(coldStorages, common.FLOW_LOG_DB, common.L4_FLOW_ID.String())),
		newFlowLogTable(common.L7_FLOW_ID, jsonify.L7FlowLogColumns(), engine, cluster, storagePolicy, l7LogTtl, ckdb.GetColdStorage(coldStorages, common.FLOW_LOG_DB, common.L7_FLOW_ID.String())),
		newFlowLogTable(common.L4_PACKET_ID, jsonify.L4PacketColumns(), engine, cluster, storagePolicy, l4PacketTtl, ckdb.GetColdStorage(coldStorages, common.FLOW_LOG_DB, common.L4_PACKET_ID.String())),
		newFlowLogTable(common.L4_PCAP_FLOW_ID, jsonify.L4FlowLogColumns(), engine, cluster, storagePolicy, l4LogTtl, ckdb.GetColdStorage(coldStorages, common.FLOW_LOG_DB, common.L4_FLOW_ID.String())),
	}
}

func NewFlowLogWriter(addr, user, password, cluster, storagePolicy string, ckWriterCfg config.CKWriterConfig, flowLogTtl streamconfig.FlowLogTTL, coldStorages map[string]*ckdb.ColdStorage) (*FlowLogWriter, error) {
	ckwriters := make([]*ckwriter.CKWriter, common.FLOWLOG_ID_MAX)
	var err error
	tables := GetFlowLogTables(ckdb.MergeTree, cluster, storagePolicy, flowLogTtl.L4FlowLog, flowLogTtl.L7FlowLog, flowLogTtl.L4Packet, coldStorages)
	for i, table := range tables {
		counterName := common.FlowLogID(table.ID).String()
		ckwriters[i], err = ckwriter.NewCKWriter(addr, "", user, password, counterName, table, false,
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

func (w *FlowLogWriter) PutPcapFlowLog(items ...interface{}) {
	w.ckwriters[common.L4_PCAP_FLOW_ID].Put(items...)
}
