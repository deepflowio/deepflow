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

package flow_tag

import (
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

const (
	FLOW_TAG_DB = "flow_tag"
)

type TagType int

const (
	TagField TagType = iota
	TagFieldValue
	TagTypeMax
)

func (t TagType) String() string {
	switch t {
	case TagField:
		return "custom_field"
	case TagFieldValue:
		return "custom_field_value"
	default:
		return "invalid tag type"
	}
}

type FieldType int

const (
	FieldTag FieldType = iota
	FieldMetrics
)

func (t FieldType) String() string {
	switch t {
	case FieldTag:
		return "tag"
	case FieldMetrics:
		return "metrics"
	default:
		return "invalid field type"
	}
}

type FlowTagInfo struct {
	table          string
	fieldType      FieldType
	vpcId          int32
	podNsId        uint16
	fieldName      string
	fieldValueType string

	hasFieldValue bool
	fieldValue    string
}

type FlowTag struct {
	pool.ReferenceCount

	Timestamp uint32 // s
	FlowTagInfo
	fieldValueCount uint64
}

func NewTagField(time uint32, db, table string, epcId int32, podNsId uint16, fieldType FieldType, fieldName string) *FlowTag {
	t := AcquireFlowTag()
	t.Timestamp = time
	t.table = table
	t.fieldType = fieldType
	t.vpcId = epcId
	t.podNsId = podNsId
	t.fieldName = fieldName
	if fieldType == FieldTag {
		t.fieldValueType = "string"
	} else {
		t.fieldValueType = "float"
	}
	return t
}

func NewTagFieldValue(time uint32, db, table string, epcId int32, podNsId uint16, fieldType FieldType, fieldName string, fieldValue string) *FlowTag {
	t := AcquireFlowTag()
	t.Timestamp = time
	t.table = table
	t.fieldType = fieldType
	t.vpcId = epcId
	t.podNsId = podNsId
	t.fieldName = fieldName
	t.fieldValueType = "string"
	t.hasFieldValue = true
	t.fieldValue = fieldValue
	return t
}

func (t *FlowTag) WriteBlock(block *ckdb.Block) {
	block.WriteDateTime(t.Timestamp)
	block.Write(
		t.table,
		t.vpcId,
		t.podNsId,
		t.fieldType.String(),
		t.fieldName,
		t.fieldValueType,
	)
	if t.hasFieldValue {
		block.Write(t.fieldValue, t.fieldValueCount)
	}
}

func (t *FlowTag) Columns() []*ckdb.Column {
	columns := []*ckdb.Column{}
	columns = append(columns,
		ckdb.NewColumn("time", ckdb.DateTime),
		ckdb.NewColumn("table", ckdb.LowCardinalityString),
		ckdb.NewColumn("vpc_id", ckdb.Int32),
		ckdb.NewColumn("pod_ns_id", ckdb.UInt16),
		ckdb.NewColumn("field_type", ckdb.LowCardinalityString).SetComment("value: tag, metrics"),
		ckdb.NewColumn("field_name", ckdb.LowCardinalityString),
		ckdb.NewColumn("field_value_type", ckdb.LowCardinalityString).SetComment("value: string, float"),
	)
	if t.hasFieldValue {
		columns = append(columns,
			ckdb.NewColumn("field_value", ckdb.String),
			ckdb.NewColumn("count", ckdb.UInt64))
	}
	return columns
}

func (t *FlowTag) GenCKTable(cluster, storagePolicy, tableName string, ttl int, partition ckdb.TimeFuncType) *ckdb.Table {
	timeKey := "time"
	engine := ckdb.ReplacingMergeTree

	orderKeys := []string{
		"table", "vpc_id", "pod_ns_id", "field_type", "field_name", "field_value_type",
	}
	if t.hasFieldValue {
		orderKeys = append(orderKeys, "field_value")
		engine = ckdb.SummingMergeTree
	}

	return &ckdb.Table{
		Database:        FLOW_TAG_DB,
		LocalName:       tableName + ckdb.LOCAL_SUBFFIX,
		GlobalName:      tableName,
		Columns:         t.Columns(),
		TimeKey:         timeKey,
		SummingKey:      "count",
		TTL:             ttl,
		PartitionFunc:   partition,
		Engine:          engine,
		Cluster:         cluster,
		StoragePolicy:   storagePolicy,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

func (t *FlowTag) Release() {
	ReleaseFlowTag(t)
}

var flowTagPool = pool.NewLockFreePool(func() interface{} {
	return &FlowTag{}
})

func AcquireFlowTag() *FlowTag {
	f := flowTagPool.Get().(*FlowTag)
	f.ReferenceCount.Reset()
	return f
}

func ReleaseFlowTag(t *FlowTag) {
	if t == nil || t.SubReferenceCount() {
		return
	}
	*t = FlowTag{}
	flowTagPool.Put(t)
}
