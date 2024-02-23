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
	"net"
	"sync/atomic"

	basecommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/flow_tag"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

const (
	DefaultPartition          = ckdb.TimeFuncTwelveHour
	DefaultPerfEventPartition = ckdb.TimeFuncHour
	IO_EVENT_TYPE_READ        = "read"
	IO_EVENT_TYPE_WRITE       = "write"
)

type SignalSource uint8

const (
	SIGNAL_SOURCE_UNKNOWN SignalSource = iota
	SIGNAL_SOURCE_RESOURCE
	SIGNAL_SOURCE_IO
)

type EventStore struct {
	Time uint32 // s
	_id  uint64

	StartTime int64
	EndTime   int64

	Tagged uint8

	SignalSource     uint8 // Resource / File IO
	EventType        string
	EventDescription string
	ProcessKName     string

	GProcessID uint32

	RegionID     uint16
	AZID         uint16
	L3EpcID      int32
	HostID       uint16
	PodID        uint32
	PodNodeID    uint32
	PodNSID      uint16
	PodClusterID uint16
	PodGroupID   uint32
	L3DeviceType uint8
	L3DeviceID   uint32
	ServiceID    uint32
	VTAPID       uint16
	SubnetID     uint16
	IsIPv4       bool
	IP4          uint32
	IP6          net.IP

	// Not stored, only determines which database to store in.
	// When Orgid is 0 or 1, it is stored in database 'event', otherwise stored in '<OrgId>_event'.
	OrgId  uint16
	TeamID uint16

	AutoInstanceID   uint32
	AutoInstanceType uint8
	AutoServiceID    uint32
	AutoServiceType  uint8

	AppInstance string

	AttributeNames  []string
	AttributeValues []string

	HasMetrics bool
	Bytes      uint32
	Duration   uint64
}

func (e *EventStore) WriteBlock(block *ckdb.Block) {
	block.WriteDateTime(e.Time)
	block.Write(
		e._id,
		e.StartTime,
		e.EndTime,

		e.Tagged,

		e.SignalSource,
		e.EventType,
		e.EventDescription,
		e.ProcessKName,

		e.GProcessID,

		e.RegionID,
		e.AZID,
		e.L3EpcID,
		e.HostID,
		e.PodID,
		e.PodNodeID,
		e.PodNSID,
		e.PodClusterID,
		e.PodGroupID,
		e.L3DeviceType,
		e.L3DeviceID,
		e.ServiceID,
		e.VTAPID,
		e.SubnetID)
	block.WriteBool(e.IsIPv4)
	block.WriteIPv4(e.IP4)
	block.WriteIPv6(e.IP6)

	block.Write(
		e.TeamID,
		e.AutoInstanceID,
		e.AutoInstanceType,
		e.AutoServiceID,
		e.AutoServiceType,
		e.AppInstance,

		e.AttributeNames,
		e.AttributeValues,
	)

	if e.HasMetrics {
		block.Write(
			e.Bytes,
			e.Duration,
		)
	}
}

func (e *EventStore) OrgID() uint16 {
	return e.OrgId
}

func (e *EventStore) Table() string {
	if e.HasMetrics {
		return common.PERF_EVENT.TableName()
	}
	return common.RESOURCE_EVENT.TableName()
}

func (e *EventStore) Release() {
	ReleaseEventStore(e)
}

var EventCounter uint32

func (e *EventStore) SetId(time, analyzerID uint32) {
	count := atomic.AddUint32(&EventCounter, 1)
	// The high 32 bits of time, 23-32 bits represent analyzerId, the low 22 bits are counter
	e._id = uint64(time)<<32 | uint64(analyzerID&0x3ff)<<22 | (uint64(count) & 0x3fffff)
}

func EventColumns(hasMetrics bool) []*ckdb.Column {
	columns := []*ckdb.Column{
		ckdb.NewColumn("time", ckdb.DateTime),
		ckdb.NewColumn("_id", ckdb.UInt64),
		ckdb.NewColumn("start_time", ckdb.DateTime64us).SetComment("精度: 微秒"),
		ckdb.NewColumn("end_time", ckdb.DateTime64us).SetComment("精度: 微秒"),

		ckdb.NewColumn("tagged", ckdb.UInt8).SetComment("标签是否为填充, 用于调试"),

		ckdb.NewColumn("signal_source", ckdb.UInt8).SetComment("事件来源"),
		ckdb.NewColumn("event_type", ckdb.LowCardinalityString).SetComment("事件类型"),
		ckdb.NewColumn("event_desc", ckdb.String).SetComment("事件信息"),
		ckdb.NewColumn("process_kname", ckdb.String).SetComment("进程名"),

		ckdb.NewColumn("gprocess_id", ckdb.UInt32).SetComment("全局进程ID"),

		ckdb.NewColumn("region_id", ckdb.UInt16).SetComment("云平台区域ID"),
		ckdb.NewColumn("az_id", ckdb.UInt16).SetComment("可用区ID"),
		ckdb.NewColumn("l3_epc_id", ckdb.Int32).SetComment("ip对应的EPC ID"),
		ckdb.NewColumn("host_id", ckdb.UInt16).SetComment("宿主机ID"),
		ckdb.NewColumn("pod_id", ckdb.UInt32).SetComment("容器ID"),
		ckdb.NewColumn("pod_node_id", ckdb.UInt32).SetComment("容器节点ID"),
		ckdb.NewColumn("pod_ns_id", ckdb.UInt16).SetComment("容器命名空间ID"),
		ckdb.NewColumn("pod_cluster_id", ckdb.UInt16).SetComment("容器集群ID"),
		ckdb.NewColumn("pod_group_id", ckdb.UInt32).SetComment("容器组ID"),

		ckdb.NewColumn("l3_device_type", ckdb.UInt8).SetComment("资源类型"),
		ckdb.NewColumn("l3_device_id", ckdb.UInt32).SetComment("资源ID"),
		ckdb.NewColumn("service_id", ckdb.UInt32).SetComment("服务ID"),
		ckdb.NewColumn("agent_id", ckdb.UInt16).SetComment("采集器ID"),
		ckdb.NewColumn("subnet_id", ckdb.UInt16),
		ckdb.NewColumn("is_ipv4", ckdb.UInt8),
		ckdb.NewColumn("ip4", ckdb.IPv4),
		ckdb.NewColumn("ip6", ckdb.IPv6),

		ckdb.NewColumn("team_id", ckdb.UInt16).SetComment("Team ID"),

		ckdb.NewColumn("auto_instance_id", ckdb.UInt32),
		ckdb.NewColumn("auto_instance_type", ckdb.UInt8),
		ckdb.NewColumn("auto_service_id", ckdb.UInt32),
		ckdb.NewColumn("auto_service_type", ckdb.UInt8),
		ckdb.NewColumn("app_instance", ckdb.String).SetComment("app instance"),

		ckdb.NewColumn("attribute_names", ckdb.ArrayLowCardinalityString).SetComment("额外的属性"),
		ckdb.NewColumn("attribute_values", ckdb.ArrayString).SetComment("额外的属性对应的值"),
	}
	if hasMetrics {
		columns = append(columns,
			ckdb.NewColumn("bytes", ckdb.UInt32),
			ckdb.NewColumn("duration", ckdb.UInt64).SetComment("精度: 微秒"),
		)
	}
	return columns
}

func GenEventCKTable(cluster, storagePolicy, table string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	timeKey := "time"
	engine := ckdb.MergeTree
	orderKeys := []string{timeKey, "signal_source", "event_type", "l3_epc_id", "l3_device_type", "l3_device_id"}
	hasMetrics := false
	partition := DefaultPartition
	if table == common.PERF_EVENT.TableName() {
		hasMetrics = true
		partition = DefaultPerfEventPartition
	}

	return &ckdb.Table{
		Version:         basecommon.CK_VERSION,
		Database:        EVENT_DB,
		LocalName:       table + ckdb.LOCAL_SUBFFIX,
		GlobalName:      table,
		Columns:         EventColumns(hasMetrics),
		TimeKey:         timeKey,
		TTL:             ttl,
		PartitionFunc:   partition,
		Engine:          engine,
		Cluster:         cluster,
		StoragePolicy:   storagePolicy,
		ColdStorage:     *coldStorage,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

func (e *EventStore) GenerateNewFlowTags(cache *flow_tag.FlowTagCache) {
	// reset temporary buffers
	flowTagInfo := &cache.FlowTagInfoBuffer
	*flowTagInfo = flow_tag.FlowTagInfo{
		Table:   e.Table(),
		VpcId:   e.L3EpcID,
		PodNsId: e.PodNSID,
		OrgId:   e.OrgId,
		TeamID:  e.TeamID,
	}
	cache.Fields = cache.Fields[:0]
	cache.FieldValues = cache.FieldValues[:0]

	// tags
	flowTagInfo.FieldType = flow_tag.FieldTag
	for i, name := range e.AttributeNames {
		flowTagInfo.FieldName = name

		// tag + value
		flowTagInfo.FieldValue = e.AttributeValues[i]
		if old, ok := cache.FieldValueCache.AddOrGet(*flowTagInfo, e.Time); ok {
			if old+cache.CacheFlushTimeout >= e.Time {
				// If there is no new fieldValue, of course there will be no new field.
				// So we can just skip the rest of the process in the loop.
				continue
			} else {
				cache.FieldValueCache.Add(*flowTagInfo, e.Time)
			}
		}
		tagFieldValue := flow_tag.AcquireFlowTag(flow_tag.TagFieldValue)
		tagFieldValue.Timestamp = e.Time
		tagFieldValue.FlowTagInfo = *flowTagInfo
		cache.FieldValues = append(cache.FieldValues, tagFieldValue)

		// only tag
		flowTagInfo.FieldValue = ""
		if old, ok := cache.FieldCache.AddOrGet(*flowTagInfo, e.Time); ok {
			if old+cache.CacheFlushTimeout >= e.Time {
				continue
			} else {
				cache.FieldCache.Add(*flowTagInfo, e.Time)
			}
		}
		tagField := flow_tag.AcquireFlowTag(flow_tag.TagField)
		tagField.Timestamp = e.Time
		tagField.FlowTagInfo = *flowTagInfo
		cache.Fields = append(cache.Fields, tagField)
	}
}

var eventPool = pool.NewLockFreePool(func() interface{} {
	return &EventStore{
		AttributeNames:  []string{},
		AttributeValues: []string{},
	}
})

func AcquireEventStore() *EventStore {
	return eventPool.Get().(*EventStore)
}

func ReleaseEventStore(e *EventStore) {
	if e == nil {
		return
	}
	attributeNames := e.AttributeNames[:0]
	attributeValues := e.AttributeValues[:0]
	*e = EventStore{}
	e.AttributeNames = attributeNames
	e.AttributeValues = attributeValues
	e.IsIPv4 = true

	eventPool.Put(e)
}
