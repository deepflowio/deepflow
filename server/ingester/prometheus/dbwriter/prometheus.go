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

package dbwriter

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_tag"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
)

const (
	DefaultPartition           = ckdb.TimeFuncTwoHour
	MIN_APP_LABEL_COLUMN_INDEX = 4
	MAX_APP_LABEL_COLUMN_INDEX = 256
)

type Prometheus struct {
	Timestamp        uint32 // s
	MetricID         uint32
	TargetID         uint32
	AppLabelValueIDs []uint32

	UniversalTag zerodoc.UniversalTag

	Value float64
}

func (m *Prometheus) DatabaseName() string {
	return PROMETHEUS_DB
}

func (m *Prometheus) TableName() string {
	return PROMETHEUS_TABLE
}

func (m *Prometheus) VirtualTableName() string {
	return ""
}

// Note: The order of Write() must be consistent with the order of append() in Columns.
func (m *Prometheus) WriteBlock(block *ckdb.Block) {
	block.WriteDateTime(m.Timestamp)
	block.Write(
		m.MetricID,
		m.TargetID,
	)
	for _, v := range m.AppLabelValueIDs[1:] {
		block.Write(v)
	}
	m.UniversalTag.WriteBlock(block)
	block.Write(m.Value)
}

// Note: The order of append() must be consistent with the order of Write() in WriteBlock.
func (m *Prometheus) Columns(appLabelColumnCount int) []*ckdb.Column {
	columns := []*ckdb.Column{}

	columns = append(columns, ckdb.NewColumnWithGroupBy("time", ckdb.DateTime))
	columns = append(columns,
		ckdb.NewColumn("metric_id", ckdb.UInt32).SetComment("encoded ID of the metric name"),
		ckdb.NewColumn("target_id", ckdb.UInt32).SetComment("the encoded ID of the target"),
	)
	for i := 1; i <= appLabelColumnCount; i++ {
		columns = append(columns, ckdb.NewColumn(fmt.Sprintf("app_label_value_id_%d", i), ckdb.UInt32))
	}
	columns = zerodoc.GenUniversalTagColumns(columns)
	columns = append(columns, ckdb.NewColumn("value", ckdb.Float64))

	return columns
}

func (m *Prometheus) Release() {
	ReleasePrometheus(m)
}

func (m *Prometheus) GenCKTable(cluster, storagePolicy string, ttl int, coldStorage *ckdb.ColdStorage, appLabelColumnCount int) *ckdb.Table {
	timeKey := "time"
	engine := ckdb.MergeTree

	// order key
	orderKeys := []string{}
	orderKeys = append(orderKeys, "metric_id")
	orderKeys = append(orderKeys, "target_id")
	orderKeys = append(orderKeys, timeKey)

	return &ckdb.Table{
		Version:         common.CK_VERSION,
		Database:        m.DatabaseName(),
		LocalName:       m.TableName() + ckdb.LOCAL_SUBFFIX,
		GlobalName:      m.TableName(),
		Columns:         m.Columns(appLabelColumnCount),
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

// Check if there is a TagName/TagValue/MetricsName not in fieldCache or fieldValueCache, and store the newly appeared item in cache.
func (m *Prometheus) GenerateNewFlowTags(cache *flow_tag.FlowTagCache, labelNames, labelValues []string) {
	tableName := m.VirtualTableName()

	// reset temporary buffers
	flowTagInfo := &cache.FlowTagInfoBuffer
	*flowTagInfo = flow_tag.FlowTagInfo{
		Table:   tableName,
		VpcId:   m.UniversalTag.L3EpcID,
		PodNsId: m.UniversalTag.PodNSID,
	}
	cache.Fields = cache.Fields[:0]
	cache.FieldValues = cache.FieldValues[:0]

	// tags
	flowTagInfo.FieldType = flow_tag.FieldTag
	for i, name := range labelNames {
		flowTagInfo.FieldName = name

		// tag + value
		flowTagInfo.FieldValue = labelValues[i]
		v1 := m.Timestamp
		if old := cache.FieldValueCache.AddOrGet(*flowTagInfo, &v1); old != nil {
			oldv, _ := old.(*uint32)
			if *oldv+cache.CacheFlushTimeout >= m.Timestamp {
				// If there is no new fieldValue, of course there will be no new field.
				// So we can just skip the rest of the process in the loop.
				continue
			} else {
				*oldv = m.Timestamp
			}
		}
		tagFieldValue := flow_tag.AcquireFlowTag()
		tagFieldValue.Timestamp = m.Timestamp
		tagFieldValue.FlowTagInfo = *flowTagInfo
		cache.FieldValues = append(cache.FieldValues, tagFieldValue)

		// only tag
		flowTagInfo.FieldValue = ""
		v2 := m.Timestamp
		if old := cache.FieldCache.AddOrGet(*flowTagInfo, &v2); old != nil {
			oldv, _ := old.(*uint32)
			if *oldv+cache.CacheFlushTimeout >= m.Timestamp {
				continue
			} else {
				*oldv = m.Timestamp
			}
		}
		tagField := flow_tag.AcquireFlowTag()
		tagField.Timestamp = m.Timestamp
		tagField.FlowTagInfo = *flowTagInfo
		cache.Fields = append(cache.Fields, tagField)
	}

}

var prometheusPool = pool.NewLockFreePool(func() interface{} {
	return &Prometheus{}
})

func AcquirePrometheus() *Prometheus {
	return prometheusPool.Get().(*Prometheus)
}

var emptyUniversalTag = zerodoc.UniversalTag{}

func ReleasePrometheus(p *Prometheus) {
	p.UniversalTag = emptyUniversalTag
	p.AppLabelValueIDs = p.AppLabelValueIDs[:0]
	prometheusPool.Put(p)
}
