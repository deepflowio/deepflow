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
	"github.com/deepflowio/deepflow/server/ingester/flow_tag"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/zerodoc"
)

const (
	DefaultPartition = ckdb.TimeFuncTwelveHour
)

type ExtMetrics struct {
	Timestamp uint32 // s

	Tag zerodoc.Tag

	Database         string
	TableName        string
	VirtualTableName string

	TagNames  []string
	TagValues []string

	MetricsFloatNames  []string
	MetricsFloatValues []float64

	fields      []interface{}
	fieldValues []interface{}
}

func (m *ExtMetrics) WriteBlock(block *ckdb.Block) {
	m.Tag.WriteBlock(block, m.Timestamp)

	if m.VirtualTableName != "" {
		block.Write(m.VirtualTableName)
	}
	block.Write(
		m.TagNames,
		m.TagValues,
		m.MetricsFloatNames,
		m.MetricsFloatValues)
}

func (m *ExtMetrics) Columns() []*ckdb.Column {
	columns := zerodoc.GenTagColumns(m.Tag.Code)
	if m.VirtualTableName != "" {
		columns = append(columns, ckdb.NewColumn("virtual_table_name", ckdb.LowCardinalityString).SetComment("虚拟表名k"))
	}
	columns = append(columns,
		ckdb.NewColumn("tag_names", ckdb.ArrayString).SetComment("额外的tag"),
		ckdb.NewColumn("tag_values", ckdb.ArrayString).SetComment("额外的tag对应的值"),
		ckdb.NewColumn("metrics_float_names", ckdb.ArrayString).SetComment("额外的float类型metrics"),
		ckdb.NewColumn("metrics_float_values", ckdb.ArrayFloat64).SetComment("额外的float metrics值"),
	)
	return columns
}

func (m *ExtMetrics) Release() {
	ReleaseExtMetrics(m)
}

func (m *ExtMetrics) GenCKTable(cluster, storagePolicy string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	timeKey := "time"
	engine := ckdb.MergeTree

	orderKeys := []string{}
	if m.VirtualTableName != "" {
		orderKeys = append(orderKeys, "virtual_table_name")
	}
	if m.Tag.Code&zerodoc.L3EpcID != 0 {
		orderKeys = append(orderKeys, "l3_epc_id")
	}
	if m.Tag.Code&zerodoc.IP != 0 {
		orderKeys = append(orderKeys, "ip4")
		orderKeys = append(orderKeys, "ip6")
	}
	orderKeys = append(orderKeys, timeKey)

	return &ckdb.Table{
		Database:        m.Database,
		LocalName:       m.TableName + ckdb.LOCAL_SUBFFIX,
		GlobalName:      m.TableName,
		Columns:         m.Columns(),
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

// Check if there is a TagName/TagValue/MetricsName not in fieldMap or fieldValueMap, and return the newly appeared item.
func (m *ExtMetrics) GenerateNewFlowTags(fieldMap, fieldValueMap map[flow_tag.FlowTagInfo]*flow_tag.FlowTag) ([]interface{}, []interface{}) {
	tableName := m.TableName
	if m.VirtualTableName != "" {
		tableName = m.VirtualTableName
	}

	for i, name := range m.TagNames {
		tagFieldValue := flow_tag.NewTagFieldValue(m.Timestamp, m.Database, tableName, int32(m.Tag.L3EpcID), m.Tag.PodNSID, flow_tag.FieldTag, name, m.TagValues[i])
		if _, ok := fieldValueMap[tagFieldValue.FlowTagInfo]; ok {
			tagFieldValue.Release()
			// If there is no new fieldValue, of course there will be no new field.
			// So we can just skip the rest of the process in the loop.
			continue
		}
		fieldValueMap[tagFieldValue.FlowTagInfo] = tagFieldValue
		m.fieldValues = append(m.fieldValues, tagFieldValue)

		tagField := flow_tag.NewTagField(m.Timestamp, m.Database, tableName, int32(m.Tag.L3EpcID), m.Tag.PodNSID, flow_tag.FieldTag, name)
		if _, ok := fieldMap[tagField.FlowTagInfo]; ok {
			tagField.Release()
			continue
		}
		fieldMap[tagField.FlowTagInfo] = tagField
		m.fields = append(m.fields, tagField)
	}

	for _, name := range m.MetricsFloatNames {
		tagField := flow_tag.NewTagField(m.Timestamp, m.Database, tableName, int32(m.Tag.L3EpcID), m.Tag.PodNSID, flow_tag.FieldMetrics, name)
		if _, ok := fieldMap[tagField.FlowTagInfo]; ok {
			tagField.Release()
			continue
		}
		fieldMap[tagField.FlowTagInfo] = tagField
		m.fields = append(m.fields, tagField)
	}

	return m.fields, m.fieldValues
}

var extMetricsPool = pool.NewLockFreePool(func() interface{} {
	return &ExtMetrics{
		Tag: zerodoc.Tag{
			Field: &zerodoc.Field{},
		},
	}
})

func AcquireExtMetrics() *ExtMetrics {
	return extMetricsPool.Get().(*ExtMetrics)
}

func ReleaseExtMetrics(m *ExtMetrics) {
	*m.Tag.Field = zerodoc.Field{}
	m.Tag.Code = 0
	m.TagNames = m.TagNames[:0]
	m.TagValues = m.TagValues[:0]
	m.MetricsFloatNames = m.MetricsFloatNames[:0]
	m.MetricsFloatValues = m.MetricsFloatValues[:0]
	m.fields = m.fields[:0]
	m.fieldValues = m.fieldValues[:0]
	extMetricsPool.Put(m)
}
