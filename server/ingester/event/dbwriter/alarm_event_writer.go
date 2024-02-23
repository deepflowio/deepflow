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
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

var alarmEventPool = pool.NewLockFreePool(func() interface{} {
	return &AlarmEventStore{}
})

func AcquireAlarmEventStore() *AlarmEventStore {
	return alarmEventPool.Get().(*AlarmEventStore)
}

func ReleaseAlarmEventStore(e *AlarmEventStore) {
	if e == nil {
		return
	}
	*e = AlarmEventStore{}
	alarmEventPool.Put(e)
}

type AlarmEventStore struct {
	Time   uint32
	Lcuuid string
	User   string
	UserId uint32

	PolicyId                uint32
	PolicyName              string
	PolicyLevel             uint32
	PolicyAppType           uint32
	PolicySubType           uint32
	PolicyContrastType      uint32
	PolicyDataLevel         string
	PolicyTargetUid         string
	PolicyTargetName        string
	PolicyGoTo              string
	PolicyTargetField       string
	PolicyEndpoints         string
	TriggerCondition        string
	TriggerValue            float64
	ValueUnit               string
	EventLevel              uint32
	AlarmTarget             string
	RegionId                uint16
	PolicyQueryUrl          string
	PolicyQueryConditions   string
	PolicyThresholdCritical string
	PolicyThresholdError    string
	PolicyThresholdWarning  string
	OrgId                   uint16
	TeamID                  uint16
}

func AlarmEventColumns() []*ckdb.Column {
	return []*ckdb.Column{
		ckdb.NewColumn("time", ckdb.DateTime),
		ckdb.NewColumn("lccuid", ckdb.String),
		ckdb.NewColumn("user", ckdb.LowCardinalityString),
		ckdb.NewColumn("user_id", ckdb.UInt32),

		ckdb.NewColumn("policy_id", ckdb.UInt32),
		ckdb.NewColumn("policy_name", ckdb.LowCardinalityString),
		ckdb.NewColumn("policy_level", ckdb.UInt32),
		ckdb.NewColumn("policy_app_type", ckdb.UInt32),
		ckdb.NewColumn("policy_sub_type", ckdb.UInt32),
		ckdb.NewColumn("policy_contrast_type", ckdb.UInt32),
		ckdb.NewColumn("policy_data_level", ckdb.LowCardinalityString),
		ckdb.NewColumn("policy_target_uid", ckdb.String),
		ckdb.NewColumn("policy_target_name", ckdb.String),
		ckdb.NewColumn("policy_go_to", ckdb.String),
		ckdb.NewColumn("policy_target_field", ckdb.String),
		ckdb.NewColumn("policy_endpoints", ckdb.LowCardinalityString),
		ckdb.NewColumn("trigger_condition", ckdb.String),
		ckdb.NewColumn("trigger_value", ckdb.Float64),
		ckdb.NewColumn("value_unit", ckdb.LowCardinalityString),
		ckdb.NewColumn("event_level", ckdb.UInt32),
		ckdb.NewColumn("alarm_target", ckdb.LowCardinalityString),
		ckdb.NewColumn("region_id", ckdb.UInt16),
		ckdb.NewColumn("policy_query_url", ckdb.String),
		ckdb.NewColumn("policy_query_conditions", ckdb.String),
		ckdb.NewColumn("policy_threshold_critical", ckdb.String),
		ckdb.NewColumn("policy_threshold_error", ckdb.String),
		ckdb.NewColumn("policy_threshold_warning", ckdb.String),
		ckdb.NewColumn("team_id", ckdb.UInt16),
	}
}

func (e *AlarmEventStore) WriteBlock(block *ckdb.Block) {
	block.WriteDateTime(e.Time)
	block.Write(
		e.Lcuuid,
		e.User,
		e.UserId,
		e.PolicyId,
		e.PolicyName,
		e.PolicyLevel,
		e.PolicyAppType,
		e.PolicySubType,
		e.PolicyContrastType,
		e.PolicyDataLevel,
		e.PolicyTargetUid,
		e.PolicyTargetName,
		e.PolicyGoTo,
		e.PolicyTargetField,
		e.PolicyEndpoints,
		e.TriggerCondition,
		e.TriggerValue,
		e.ValueUnit,
		e.EventLevel,
		e.AlarmTarget,
		e.RegionId,
		e.PolicyQueryUrl,
		e.PolicyQueryConditions,
		e.PolicyThresholdCritical,
		e.PolicyThresholdError,
		e.PolicyThresholdWarning,
		e.TeamID,
	)
}

func (e *AlarmEventStore) Release() {
	ReleaseAlarmEventStore(e)
}

func (e *AlarmEventStore) OrgID() uint16 {
	return e.OrgId
}

func GenAlarmEventCKTable(cluster, storagePolicy string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	table := common.ALARM_EVENT.TableName()
	timeKey := "time"
	engine := ckdb.MergeTree
	orderKeys := []string{"time", "policy_id", "policy_name"}

	return &ckdb.Table{
		Version:         basecommon.CK_VERSION,
		Database:        EVENT_DB,
		LocalName:       table + ckdb.LOCAL_SUBFFIX,
		GlobalName:      table,
		Columns:         AlarmEventColumns(),
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

func NewAlarmEventWriter(config *config.Config) (*EventWriter, error) {
	w := &EventWriter{
		ckdbAddrs:         config.Base.CKDB.ActualAddrs,
		ckdbUsername:      config.Base.CKDBAuth.Username,
		ckdbPassword:      config.Base.CKDBAuth.Password,
		ckdbCluster:       config.Base.CKDB.ClusterName,
		ckdbStoragePolicy: config.Base.CKDB.StoragePolicy,
		ckdbColdStorages:  config.Base.GetCKDBColdStorages(),
		ttl:               config.AlarmTTL,
		writerConfig:      config.CKWriterConfig,
	}

	ckTable := GenAlarmEventCKTable(w.ckdbCluster, w.ckdbStoragePolicy, w.ttl, ckdb.GetColdStorage(w.ckdbColdStorages, EVENT_DB, common.ALARM_EVENT.TableName()))

	ckwriter, err := ckwriter.NewCKWriter(w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
		common.ALARM_EVENT.TableName(), config.Base.CKDB.TimeZone, ckTable, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout, config.Base.CKDB.Watcher)
	if err != nil {
		return nil, err
	}
	w.ckWriter = ckwriter
	w.ckWriter.Run()
	return w, nil
}
