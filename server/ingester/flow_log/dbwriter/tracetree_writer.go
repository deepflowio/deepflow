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
	basecommon "github.com/deepflowio/deepflow/server/ingester/common"
	baseconfig "github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_log/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/queue"
	"github.com/deepflowio/deepflow/server/libs/tracetree"
)

const (
	TRACE_TREE_TABLE = "trace_tree"
	BUFFER_SIZE      = 1024
)

func GenTraceTreeCKTable(cluster, storagePolicy, ckdbType string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	table := TRACE_TREE_TABLE
	timeKey := "time"
	engine := ckdb.MergeTree
	orderKeys := []string{"search_index", "time"}

	return &ckdb.Table{
		Version:         basecommon.CK_VERSION,
		Database:        common.FLOW_LOG_DB,
		DBType:          ckdbType,
		LocalName:       table + ckdb.LOCAL_SUBFFIX,
		GlobalName:      table,
		Columns:         tracetree.TraceTreeColumns(),
		TimeKey:         timeKey,
		TTL:             ttl,
		PartitionFunc:   DefaultPartition,
		Engine:          engine,
		Cluster:         cluster,
		StoragePolicy:   storagePolicy,
		ColdStorage:     *coldStorage,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

type TraceTreeWriter struct {
	ckdbAddrs         *[]string
	ckdbUsername      string
	ckdbPassword      string
	ckdbCluster       string
	ckdbStoragePolicy string
	ckdbColdStorages  map[string]*ckdb.ColdStorage
	ttl               int
	writerConfig      baseconfig.CKWriterConfig

	traceWriter    *ckwriter.CKWriter
	traceTreeQueue queue.QueueReader
}

func NewTraceTreeWriter(config *config.Config, traceTreeQueue queue.QueueReader) (*TraceTreeWriter, error) {
	if !*config.TraceTreeEnabled {
		return nil, nil
	}

	w := &TraceTreeWriter{
		ckdbAddrs:         config.Base.CKDB.ActualAddrs,
		ckdbUsername:      config.Base.CKDBAuth.Username,
		ckdbPassword:      config.Base.CKDBAuth.Password,
		ckdbCluster:       config.Base.CKDB.ClusterName,
		ckdbStoragePolicy: config.Base.CKDB.StoragePolicy,
		ckdbColdStorages:  config.Base.GetCKDBColdStorages(),
		ttl:               config.FlowLogTTL.L7FlowLog,
		writerConfig:      config.CKWriterConfig,
		traceTreeQueue:    traceTreeQueue,
	}

	ckTable := GenTraceTreeCKTable(w.ckdbCluster, w.ckdbStoragePolicy, config.Base.CKDB.Type, w.ttl, ckdb.GetColdStorage(w.ckdbColdStorages, common.FLOW_LOG_DB, TRACE_TREE_TABLE))

	ckwriter, err := ckwriter.NewCKWriter(*w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
		TRACE_TREE_TABLE, config.Base.CKDB.TimeZone, ckTable, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout, config.Base.CKDB.Watcher)
	if err != nil {
		return nil, err
	}
	w.traceWriter = ckwriter

	return w, nil
}

func (s *TraceTreeWriter) Put(items []interface{}) {
	s.traceWriter.Put(items...)
}

func (s *TraceTreeWriter) Start() {
	go s.run()
}

func (s *TraceTreeWriter) run() {
	log.Infof("flow log trace tree writer starting")
	s.traceWriter.Run()
	buffer := make([]interface{}, BUFFER_SIZE)
	for {
		n := s.traceTreeQueue.Gets(buffer)
		for i := 0; i < n; i++ {
			if buffer[i] == nil {
				continue
			}
			traceTree, ok := buffer[i].(*tracetree.TraceTree)
			if !ok {
				log.Warning("trace tree wrong type")
				continue
			}
			s.traceWriter.Put(traceTree)
		}
	}
}

func (s *TraceTreeWriter) Close() {
	s.traceWriter.Close()
}
