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
	"fmt"

	"github.com/deepflowys/deepflow/server/libs/ckdb"
	"github.com/deepflowys/deepflow/server/libs/pool"
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

type FlowTag struct {
	Timestamp uint32 // s
	TableName string

	table          string
	fieldType      FieldType
	vpcId          int32
	podNsId        uint16
	fieldName      string
	fieldValueType string

	hasFieldValue bool
	fieldValue    string
}

func NewTagField(time uint32, db, table string, epcId int32, podNsId uint16, fieldType FieldType, fieldName string) *FlowTag {
	t := AcquireFlowTag()
	t.Timestamp = time
	t.TableName = fmt.Sprintf("%s_%s", db, TagField.String())
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
	t.TableName = fmt.Sprintf("%s_%s", db, TagFieldValue.String())
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

func (t *FlowTag) WriteBlock(block *ckdb.Block) error {
	if err := block.WriteDateTime(t.Timestamp); err != nil {
		return err
	}
	if err := block.WriteString(t.table); err != nil {
		return err
	}
	if err := block.WriteInt32(t.vpcId); err != nil {
		return err
	}
	if err := block.WriteUInt16(t.podNsId); err != nil {
		return err
	}
	if err := block.WriteString(t.fieldType.String()); err != nil {
		return err
	}
	if err := block.WriteString(t.fieldName); err != nil {
		return err
	}
	if err := block.WriteString(t.fieldValueType); err != nil {
		return err
	}

	if t.hasFieldValue {
		if err := block.WriteString(t.fieldValue); err != nil {
			return err
		}
		if err := block.WriteUInt64(1); err != nil {
			return err
		}
	}
	return nil
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

func (t *FlowTag) GenCKTable(ttl int, partition ckdb.TimeFuncType) *ckdb.Table {
	timeKey := "time"
	cluster := ckdb.DF_CLUSTER
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
		LocalName:       t.TableName + ckdb.LOCAL_SUBFFIX,
		GlobalName:      t.TableName,
		Columns:         t.Columns(),
		TimeKey:         timeKey,
		SummingKey:      "count",
		TTL:             ttl,
		PartitionFunc:   partition,
		Engine:          engine,
		Cluster:         cluster,
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
	return flowTagPool.Get().(*FlowTag)
}

func ReleaseFlowTag(t *FlowTag) {
	*t = FlowTag{}
	flowTagPool.Put(t)
}
