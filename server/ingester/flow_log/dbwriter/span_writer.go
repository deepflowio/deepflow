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
	logdata "github.com/deepflowio/deepflow/server/ingester/flow_log/log_data"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/codec"
	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/tracetree"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	SPAN_WITH_TRACE_ID_TABLE = "span_with_trace_id"
)

type SpanWithTraceID logdata.L7FlowLog

func (t *SpanWithTraceID) WriteBlock(block *ckdb.Block) {
	t.Encode()
	block.WriteDateTime(t.Time)
	block.Write(
		t.TraceId,
		t.TraceIdIndex,
		utils.String(t.EncodedSpan),
	)
}

func SpanWithTraceIDColumns() []*ckdb.Column {
	return []*ckdb.Column{
		ckdb.NewColumn("time", ckdb.DateTime),
		ckdb.NewColumn("trace_id", ckdb.String),
		ckdb.NewColumn("search_index", ckdb.UInt64),
		ckdb.NewColumn("encoded_span", ckdb.String),
	}
}

func (t *SpanWithTraceID) OrgID() uint16 {
	return t.OrgId
}

func (t *SpanWithTraceID) Release() {
	logdata.ReleaseL7FlowLog((*logdata.L7FlowLog)(t))
}

func (t *SpanWithTraceID) Encode() {
	encoder := &codec.SimpleEncoder{}
	t.EncodedSpan = t.EncodedSpan[:0]
	encoder.Init(t.EncodedSpan)
	encoder.WriteU8(tracetree.SPAN_TRACE_VERSION)
	encoder.WriteU32(uint32(t.EndTime % 1000000)) // only encode microsecond part less than 1 second
	encoder.WriteU8(t.AutoServiceType0)
	encoder.WriteU8(t.AutoServiceType1)
	encoder.WriteVarintU32(t.AutoServiceID0)
	encoder.WriteVarintU32(t.AutoServiceID1)
	encoder.WriteBool(t.IsIPv4)
	if t.IsIPv4 {
		encoder.WriteU32(t.IP40)
		encoder.WriteU32(t.IP41)
	} else {
		encoder.WriteIPv6(t.IP60)
		encoder.WriteIPv6(t.IP61)
	}
	encoder.WriteVarintU32(t.ProcessID0)
	encoder.WriteVarintU32(t.ProcessID1)
	encoder.WriteU16(t.VtapID)
	encoder.WriteU8(t.TapSideEnum)
	encoder.WriteVarintU32(t.ReqTcpSeq)
	encoder.WriteVarintU32(t.RespTcpSeq)
	encoder.WriteString255(t.XRequestId0)
	encoder.WriteString255(t.XRequestId1)
	encoder.WriteString255(t.SpanId)
	encoder.WriteString255(t.ParentSpanId)
	encoder.WriteString255(t.AppService)
	// topic: currently only taken from Kafka's RequestDomain
	if t.L7Protocol == uint8(datatype.L7_PROTOCOL_KAFKA) {
		encoder.WriteString255(t.RequestDomain)
		encoder.WriteString255(t.RequestType)
	} else {
		encoder.WriteString255("")
		encoder.WriteString255("")
	}
	encoder.WriteVarintU64(t.SyscallTraceIDRequest)
	encoder.WriteVarintU64(t.SyscallTraceIDResponse)
	encoder.WriteVarintU64(t.ResponseDuration)
	encoder.WriteU8(t.ResponseStatus)
	t.EncodedSpan = encoder.Bytes()
}

func GenSpanWithTraceIDCKTable(cluster, storagePolicy, ckdbType string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	table := SPAN_WITH_TRACE_ID_TABLE
	timeKey := "time"
	engine := ckdb.MergeTree
	orderKeys := []string{"search_index", "time"}

	return &ckdb.Table{
		Version:         basecommon.CK_VERSION,
		Database:        common.FLOW_LOG_DB,
		DBType:          ckdbType,
		LocalName:       table + ckdb.LOCAL_SUBFFIX,
		GlobalName:      table,
		Columns:         SpanWithTraceIDColumns(),
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

type SpanWriter struct {
	ckdbAddrs         *[]string
	ckdbUsername      string
	ckdbPassword      string
	ckdbCluster       string
	ckdbStoragePolicy string
	ckdbColdStorages  map[string]*ckdb.ColdStorage
	ttl               int
	writerConfig      baseconfig.CKWriterConfig

	traceWriter *ckwriter.CKWriter
}

func NewSpanWriter(config *config.Config) (*SpanWriter, error) {
	if !*config.TraceTreeEnabled {
		return nil, nil
	}
	w := &SpanWriter{
		ckdbAddrs:         config.Base.CKDB.ActualAddrs,
		ckdbUsername:      config.Base.CKDBAuth.Username,
		ckdbPassword:      config.Base.CKDBAuth.Password,
		ckdbCluster:       config.Base.CKDB.ClusterName,
		ckdbStoragePolicy: config.Base.CKDB.StoragePolicy,
		ckdbColdStorages:  config.Base.GetCKDBColdStorages(),
		ttl:               config.FlowLogTTL.L7FlowLog,
		writerConfig:      config.CKWriterConfig,
	}

	ckTable := GenSpanWithTraceIDCKTable(w.ckdbCluster, w.ckdbStoragePolicy, config.Base.CKDB.Type, w.ttl, ckdb.GetColdStorage(w.ckdbColdStorages, common.FLOW_LOG_DB, SPAN_WITH_TRACE_ID_TABLE))

	ckwriter, err := ckwriter.NewCKWriter(*w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
		SPAN_WITH_TRACE_ID_TABLE, config.Base.CKDB.TimeZone, ckTable, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout, config.Base.CKDB.Watcher)
	if err != nil {
		return nil, err
	}
	w.traceWriter = ckwriter

	return w, nil
}

func (s *SpanWriter) Put(items []interface{}) {
	s.traceWriter.Put(items...)
}

func (s *SpanWriter) Start() {
	log.Info("flow log span writer starting")
	s.traceWriter.Run()
}

func (s *SpanWriter) Close() {
	s.traceWriter.Close()
}
