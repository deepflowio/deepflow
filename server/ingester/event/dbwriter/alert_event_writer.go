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
	"strconv"
	"sync/atomic"

	basecommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/config"
	"github.com/deepflowio/deepflow/server/ingester/flow_tag"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

// ─── AlertEventStore (new AlertEvent proto, ReplacingMergeTree) ───────────────

var alertEventPool = pool.NewLockFreePool(func() *AlertEventStore {
	return &AlertEventStore{}
})

func AcquireAlertEventStore() *AlertEventStore {
	return alertEventPool.Get()
}

func ReleaseAlertEventStore(e *AlertEventStore) {
	if e == nil {
		return
	}
	*e = AlertEventStore{}
	alertEventPool.Put(e)
}

type AlertEventStore struct {
	Time uint32
	_id  uint64

	PolicyId       uint32
	PolicyType     uint8
	AlertPlicy     string
	MetricValue    float64
	MetricValueStr string
	EventLevel     uint8
	TargetTags     string
	TagStrKeys     []string
	TagStrValues   []string
	TagIntKeys     []string
	TagIntValues   []int64

	TriggerThreshold string
	MetricUnit       string
	CustomTagKeys    []string
	CustomTagValues  []string

	XTargetUid   string
	XQueryRegion string

	UserId uint32
	OrgId  uint16
	TeamID uint16

	// New fields for AlertEvent
	EventId   string
	StartTime uint32
	EndTime   uint32
	Duration  uint32
	State     uint32
	AlertTime uint64
}

func (e *AlertEventStore) SetId(time, analyzerID uint32) {
	count := atomic.AddUint32(&EventCounter, 1)
	e._id = uint64(time)<<32 | uint64(analyzerID&0x3ff)<<22 | (uint64(count) & 0x3fffff)
}

func AlertEventColumns() []*ckdb.Column {
	return []*ckdb.Column{
		ckdb.NewColumn("time", ckdb.DateTime),
		ckdb.NewColumn("_id", ckdb.UInt64),

		ckdb.NewColumn("policy_id", ckdb.UInt32),
		ckdb.NewColumn("policy_type", ckdb.UInt8),
		ckdb.NewColumn("alert_policy", ckdb.LowCardinalityString),
		ckdb.NewColumn("metric_value", ckdb.Float64),
		ckdb.NewColumn("metric_value_str", ckdb.String),
		ckdb.NewColumn("event_level", ckdb.UInt8),
		ckdb.NewColumn("target_tags", ckdb.String),

		ckdb.NewColumn("tag_string_names", ckdb.ArrayLowCardinalityString),
		ckdb.NewColumn("tag_string_values", ckdb.ArrayString),
		ckdb.NewColumn("tag_int_names", ckdb.ArrayLowCardinalityString),
		ckdb.NewColumn("tag_int_values", ckdb.ArrayInt64),

		ckdb.NewColumn("trigger_threshold", ckdb.LowCardinalityString),
		ckdb.NewColumn("metric_unit", ckdb.LowCardinalityString),
		ckdb.NewColumn("custom_tag_names", ckdb.ArrayLowCardinalityString),
		ckdb.NewColumn("custom_tag_values", ckdb.ArrayString),

		ckdb.NewColumn("_target_uid", ckdb.String),
		ckdb.NewColumn("_query_region", ckdb.LowCardinalityString),

		ckdb.NewColumn("team_id", ckdb.UInt16),
		ckdb.NewColumn("user_id", ckdb.UInt32),

		// New columns
		ckdb.NewColumn("event_id", ckdb.String),
		ckdb.NewColumn("start_time", ckdb.DateTime),
		ckdb.NewColumn("end_time", ckdb.DateTime),
		ckdb.NewColumn("duration", ckdb.UInt32),
		ckdb.NewColumn("state", ckdb.UInt32),
		ckdb.NewColumn("alert_time", ckdb.UInt64),
	}
}

func (e *AlertEventStore) WriteBlock(block *ckdb.Block) {
	block.WriteDateTime(e.Time)
	block.Write(
		e._id,
		e.PolicyId,
		e.PolicyType,
		e.AlertPlicy,
		e.MetricValue,
		e.MetricValueStr,
		e.EventLevel,
		e.TargetTags,

		e.TagStrKeys,
		e.TagStrValues,
		e.TagIntKeys,
		e.TagIntValues,

		e.TriggerThreshold,
		e.MetricUnit,
		e.CustomTagKeys,
		e.CustomTagValues,

		e.XTargetUid,
		e.XQueryRegion,

		e.TeamID,
		e.UserId,

		e.EventId,
	)
	block.WriteDateTime(e.StartTime)
	block.WriteDateTime(e.EndTime)
	block.Write(
		e.Duration,
		e.State,
		e.AlertTime,
	)
}

func (e *AlertEventStore) Release() {
	ReleaseAlertEventStore(e)
}

func (e *AlertEventStore) OrgID() uint16 {
	return e.OrgId
}

func (e *AlertEventStore) Table() string {
	return common.ALERT_EVENT.TableName()
}

func (e *AlertEventStore) GenerateNewFlowTags(cache *flow_tag.FlowTagCache) {
	flowTagInfo := &cache.FlowTagInfoBuffer
	*flowTagInfo = flow_tag.FlowTagInfo{
		Table:  e.Table(),
		OrgId:  e.OrgId,
		TeamID: e.TeamID,
	}
	cache.Fields = cache.Fields[:0]
	cache.FieldValues = cache.FieldValues[:0]

	// tags
	flowTagInfo.FieldType = flow_tag.FieldTag

	tagStrLen := len(e.TagStrKeys)
	tagIntLen := len(e.TagIntKeys)
	customTagLen := len(e.CustomTagKeys)
	var name, value string
	for i := 0; i < tagStrLen+tagIntLen+customTagLen; i++ {
		if i < tagStrLen {
			name = e.TagStrKeys[i]
			value = e.TagStrValues[i]
			flowTagInfo.FieldValueType = flow_tag.FieldValueTypeString
			flowTagInfo.FieldType = flow_tag.FieldTag
		} else if i < tagStrLen+tagIntLen {
			name = e.TagIntKeys[i-tagStrLen]
			value = strconv.FormatInt(e.TagIntValues[i-tagStrLen], 10)
			flowTagInfo.FieldValueType = flow_tag.FieldValueTypeInt
			flowTagInfo.FieldType = flow_tag.FieldTag
		} else {
			name = e.CustomTagKeys[i-tagStrLen-tagIntLen]
			value = e.CustomTagValues[i-tagStrLen-tagIntLen]
			flowTagInfo.FieldValueType = flow_tag.FieldValueTypeString
			flowTagInfo.FieldType = flow_tag.FieldCustomTag
		}

		flowTagInfo.FieldName = name
		flowTagInfo.FieldValue = value
		if old, ok := cache.FieldValueCache.AddOrGet(*flowTagInfo, e.Time); ok {
			if old+cache.CacheFlushTimeout >= e.Time {
				continue
			} else {
				cache.FieldValueCache.Add(*flowTagInfo, e.Time)
			}
		}
		tagFieldValue := flow_tag.AcquireFlowTag(flow_tag.TagFieldValue)
		tagFieldValue.Timestamp = e.Time
		tagFieldValue.FlowTagInfo = *flowTagInfo
		cache.FieldValues = append(cache.FieldValues, tagFieldValue)

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

// GenAlertEventCKTable creates the alert_event table definition.
//
// Design rationale:
//   - Engine: ReplacingMergeTree(time) — for the same ORDER BY key, keep the row
//     with the highest _id (i.e., the most recently written row).
//   - ORDER BY (event_id): dedup key is event_id alone, guaranteeing globally
//     unique event_id. ClickHouse ReplacingMergeTree dedup key == ORDER BY key,
//     so time cannot be added to ORDER BY without making it part of the dedup key.
//   - PARTITION BY toYYYYMM(time) (TimeFuncDay): provides time-based partition
//     pruning for fast time-range queries without requiring time in ORDER BY.
//     Queries with a time filter skip entire month partitions automatically.
func GenAlertEventCKTable(cluster, storagePolicy, ckdbType string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	table := common.ALERT_EVENT.TableName()
	timeKey := "time"
	engine := ckdb.ReplacingMergeTree
	// Dedup key is event_id only — guarantees at most one row per event_id
	// within each daily partition (same event_id always has the same time,
	// so it always lands in the same partition → globally unique event_id).
	orderKeys := []string{"event_id"}

	return &ckdb.Table{
		Version:         basecommon.CK_VERSION,
		Database:        EVENT_DB,
		DBType:          ckdbType,
		LocalName:       table + ckdb.LOCAL_SUBFFIX,
		GlobalName:      table,
		Columns:         AlertEventColumns(),
		TimeKey:         timeKey,
		ReplacingKey:    "time",
		TTL:             ttl,
		PartitionFunc:   DefaultAlertEventPartition,
		Engine:          engine,
		Cluster:         cluster,
		StoragePolicy:   storagePolicy,
		ColdStorage:     *coldStorage,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}

func NewAlertEventWriter(config *config.Config) (*EventWriter, error) {
	w := &EventWriter{
		ckdbAddrs:         config.Base.CKDB.ActualAddrs,
		ckdbUsername:      config.Base.CKDBAuth.Username,
		ckdbPassword:      config.Base.CKDBAuth.Password,
		ckdbCluster:       config.Base.CKDB.ClusterName,
		ckdbStoragePolicy: config.Base.CKDB.StoragePolicy,
		ckdbColdStorages:  config.Base.GetCKDBColdStorages(),
		ttl:               config.AlertEventTTL,
		writerConfig:      config.CKWriterConfig,
	}

	flowTagWriter, err := flow_tag.NewFlowTagWriter(0, common.ALERT_EVENT.String(), EVENT_DB, w.ttl, ckdb.TimeFuncTwelveHour, config.Base, &w.writerConfig)
	if err != nil {
		return nil, err
	}

	w.flowTagWriter = flowTagWriter
	ckTable := GenAlertEventCKTable(w.ckdbCluster, w.ckdbStoragePolicy, config.Base.CKDB.Type, w.ttl, ckdb.GetColdStorage(w.ckdbColdStorages, EVENT_DB, common.ALERT_EVENT.TableName()))

	ckwriter, err := ckwriter.NewCKWriter(*w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
		common.ALERT_EVENT.TableName(), config.Base.CKDB.TimeZone, ckTable, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout, config.Base.CKDB.Watcher)
	if err != nil {
		return nil, err
	}
	w.ckWriter = ckwriter
	w.ckWriter.Run()
	return w, nil
}

// ─── AlertRecordStore (AlertRecord proto, MergeTree, same structure as old AlertEvent) ──

var alertRecordPool = pool.NewLockFreePool(func() *AlertRecordStore {
	return &AlertRecordStore{}
})

func AcquireAlertRecordStore() *AlertRecordStore {
	return alertRecordPool.Get()
}

func ReleaseAlertRecordStore(e *AlertRecordStore) {
	if e == nil {
		return
	}
	*e = AlertRecordStore{}
	alertRecordPool.Put(e)
}

type AlertRecordStore struct {
	Time uint32
	_id  uint64

	PolicyId         uint32
	PolicyType       uint8
	AlertPolicy      string
	MetricValue      float64
	MetricValueStr   string
	EventLevel       uint8
	TargetTags       string
	TagStrKeys       []string
	TagStrValues     []string
	TagIntKeys       []string
	TagIntValues     []int64
	TriggerThreshold string
	MetricUnit       string
	CustomTagKeys    []string
	CustomTagValues  []string

	XTargetUid   string
	XQueryRegion string

	UserId uint32
	OrgId  uint16
	TeamID uint16

	EventId string
}

func (e *AlertRecordStore) SetId(time, analyzerID uint32) {
	count := atomic.AddUint32(&EventCounter, 1)
	e._id = uint64(time)<<32 | uint64(analyzerID&0x3ff)<<22 | (uint64(count) & 0x3fffff)
}

func AlertRecordColumns() []*ckdb.Column {
	return []*ckdb.Column{
		ckdb.NewColumn("time", ckdb.DateTime),
		ckdb.NewColumn("_id", ckdb.UInt64),

		ckdb.NewColumn("policy_id", ckdb.UInt32),
		ckdb.NewColumn("policy_type", ckdb.UInt8),
		ckdb.NewColumn("alert_policy", ckdb.LowCardinalityString),
		ckdb.NewColumn("metric_value", ckdb.Float64),
		ckdb.NewColumn("metric_value_str", ckdb.String),
		ckdb.NewColumn("event_level", ckdb.UInt8),
		ckdb.NewColumn("target_tags", ckdb.String),

		ckdb.NewColumn("tag_string_names", ckdb.ArrayLowCardinalityString),
		ckdb.NewColumn("tag_string_values", ckdb.ArrayString),
		ckdb.NewColumn("tag_int_names", ckdb.ArrayLowCardinalityString),
		ckdb.NewColumn("tag_int_values", ckdb.ArrayInt64),

		ckdb.NewColumn("trigger_threshold", ckdb.LowCardinalityString),
		ckdb.NewColumn("metric_unit", ckdb.LowCardinalityString),
		ckdb.NewColumn("custom_tag_names", ckdb.ArrayLowCardinalityString),
		ckdb.NewColumn("custom_tag_values", ckdb.ArrayString),

		ckdb.NewColumn("_target_uid", ckdb.String),
		ckdb.NewColumn("_query_region", ckdb.LowCardinalityString),

		ckdb.NewColumn("team_id", ckdb.UInt16),
		ckdb.NewColumn("user_id", ckdb.UInt32),

		ckdb.NewColumn("event_id", ckdb.String),
	}
}

func (e *AlertRecordStore) WriteBlock(block *ckdb.Block) {
	block.WriteDateTime(e.Time)
	block.Write(
		e._id,
		e.PolicyId,
		e.PolicyType,
		e.AlertPolicy,
		e.MetricValue,
		e.MetricValueStr,
		e.EventLevel,
		e.TargetTags,

		e.TagStrKeys,
		e.TagStrValues,
		e.TagIntKeys,
		e.TagIntValues,

		e.TriggerThreshold,
		e.MetricUnit,
		e.CustomTagKeys,
		e.CustomTagValues,

		e.XTargetUid,
		e.XQueryRegion,

		e.TeamID,
		e.UserId,

		e.EventId,
	)
}

func (e *AlertRecordStore) Release() {
	ReleaseAlertRecordStore(e)
}

func (e *AlertRecordStore) NativeTagVersion() uint32 {
	return 0
}

func (e *AlertRecordStore) OrgID() uint16 {
	return e.OrgId
}

func (e *AlertRecordStore) Table() string {
	return common.ALERT_RECORD.TableName()
}

func (e *AlertRecordStore) GenerateNewFlowTags(cache *flow_tag.FlowTagCache) {
	flowTagInfo := &cache.FlowTagInfoBuffer
	*flowTagInfo = flow_tag.FlowTagInfo{
		Table:  e.Table(),
		OrgId:  e.OrgId,
		TeamID: e.TeamID,
	}
	cache.Fields = cache.Fields[:0]
	cache.FieldValues = cache.FieldValues[:0]

	tagStrLen := len(e.TagStrKeys)
	tagIntLen := len(e.TagIntKeys)
	customTagLen := len(e.CustomTagKeys)
	var name, value string
	for i := 0; i < tagStrLen+tagIntLen+customTagLen; i++ {
		if i < tagStrLen {
			name = e.TagStrKeys[i]
			value = e.TagStrValues[i]
			flowTagInfo.FieldValueType = flow_tag.FieldValueTypeString
			flowTagInfo.FieldType = flow_tag.FieldTag
		} else if i < tagStrLen+tagIntLen {
			name = e.TagIntKeys[i-tagStrLen]
			value = strconv.FormatInt(e.TagIntValues[i-tagStrLen], 10)
			flowTagInfo.FieldValueType = flow_tag.FieldValueTypeInt
			flowTagInfo.FieldType = flow_tag.FieldTag
		} else {
			name = e.CustomTagKeys[i-tagStrLen-tagIntLen]
			value = e.CustomTagValues[i-tagStrLen-tagIntLen]
			flowTagInfo.FieldValueType = flow_tag.FieldValueTypeString
			flowTagInfo.FieldType = flow_tag.FieldCustomTag
		}

		flowTagInfo.FieldName = name
		flowTagInfo.FieldValue = value
		if old, ok := cache.FieldValueCache.AddOrGet(*flowTagInfo, e.Time); ok {
			if old+cache.CacheFlushTimeout >= e.Time {
				continue
			} else {
				cache.FieldValueCache.Add(*flowTagInfo, e.Time)
			}
		}
		tagFieldValue := flow_tag.AcquireFlowTag(flow_tag.TagFieldValue)
		tagFieldValue.Timestamp = e.Time
		tagFieldValue.FlowTagInfo = *flowTagInfo
		cache.FieldValues = append(cache.FieldValues, tagFieldValue)

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

func GenAlertRecordCKTable(cluster, storagePolicy, ckdbType string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	table := common.ALERT_RECORD.TableName()
	timeKey := "time"
	engine := ckdb.MergeTree
	orderKeys := []string{"time", "policy_id"}

	return &ckdb.Table{
		Version:         basecommon.CK_VERSION,
		Database:        EVENT_DB,
		DBType:          ckdbType,
		LocalName:       table + ckdb.LOCAL_SUBFFIX,
		GlobalName:      table,
		Columns:         AlertRecordColumns(),
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

func NewAlertRecordWriter(config *config.Config) (*EventWriter, error) {
	w := &EventWriter{
		ckdbAddrs:         config.Base.CKDB.ActualAddrs,
		ckdbUsername:      config.Base.CKDBAuth.Username,
		ckdbPassword:      config.Base.CKDBAuth.Password,
		ckdbCluster:       config.Base.CKDB.ClusterName,
		ckdbStoragePolicy: config.Base.CKDB.StoragePolicy,
		ckdbColdStorages:  config.Base.GetCKDBColdStorages(),
		ttl:               config.AlertRecordTTL,
		writerConfig:      config.CKWriterConfig,
	}

	flowTagWriter, err := flow_tag.NewFlowTagWriter(0, common.ALERT_RECORD.String(), EVENT_DB, w.ttl, ckdb.TimeFuncTwelveHour, config.Base, &w.writerConfig)
	if err != nil {
		return nil, err
	}

	w.flowTagWriter = flowTagWriter
	ckTable := GenAlertRecordCKTable(w.ckdbCluster, w.ckdbStoragePolicy, config.Base.CKDB.Type, w.ttl, ckdb.GetColdStorage(w.ckdbColdStorages, EVENT_DB, common.ALERT_RECORD.TableName()))

	ckwriter, err := ckwriter.NewCKWriter(*w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
		common.ALERT_RECORD.TableName(), config.Base.CKDB.TimeZone, ckTable, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout, config.Base.CKDB.Watcher)
	if err != nil {
		return nil, err
	}
	w.ckWriter = ckwriter
	w.ckWriter.Run()
	return w, nil
}
