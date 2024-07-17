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
	"sync/atomic"

	basecommon "github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/config"
	"github.com/deepflowio/deepflow/server/ingester/pkg/ckwriter"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

var alertEventPool = pool.NewLockFreePool(func() interface{} {
	return &AlertEventStore{}
})

func AcquireAlertEventStore() *AlertEventStore {
	return alertEventPool.Get().(*AlertEventStore)
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

	PolicyId     uint32
	PolicyType   uint8
	AlertPlicy   string
	MetricValue  float64
	EventLevel   uint8
	TagStrKeys   []string
	TagStrValues []string
	TagIntKeys   []string
	TagIntValues []int64

	UserId uint32
	OrgId  uint16
	TeamID uint16
}

func (e *AlertEventStore) SetId(time, analyzerID uint32) {
	count := atomic.AddUint32(&EventCounter, 1)
	// The high 32 bits of time, 23-32 bits represent analyzerId, the low 22 bits are counter
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
		ckdb.NewColumn("event_level", ckdb.UInt8),

		ckdb.NewColumn("tag_string_names", ckdb.ArrayLowCardinalityString),
		ckdb.NewColumn("tag_string_values", ckdb.ArrayString),
		ckdb.NewColumn("tag_int_names", ckdb.ArrayLowCardinalityString),
		ckdb.NewColumn("tag_int_values", ckdb.ArrayInt64),

		ckdb.NewColumn("team_id", ckdb.UInt16),
		ckdb.NewColumn("user_id", ckdb.UInt32),
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
		e.EventLevel,

		e.TagStrKeys,
		e.TagStrValues,
		e.TagIntKeys,
		e.TagIntValues,

		e.TeamID,
		e.UserId,
	)
}

func (e *AlertEventStore) Release() {
	ReleaseAlertEventStore(e)
}

func (e *AlertEventStore) OrgID() uint16 {
	return e.OrgId
}

func GenAlertEventCKTable(cluster, storagePolicy string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	table := common.ALERT_EVENT.TableName()
	timeKey := "time"
	engine := ckdb.MergeTree
	orderKeys := []string{"time", "policy_id"}

	return &ckdb.Table{
		Version:         basecommon.CK_VERSION,
		Database:        EVENT_DB,
		LocalName:       table + ckdb.LOCAL_SUBFFIX,
		GlobalName:      table,
		Columns:         AlertEventColumns(),
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

	ckTable := GenAlertEventCKTable(w.ckdbCluster, w.ckdbStoragePolicy, w.ttl, ckdb.GetColdStorage(w.ckdbColdStorages, EVENT_DB, common.ALERT_EVENT.TableName()))

	ckwriter, err := ckwriter.NewCKWriter(w.ckdbAddrs, w.ckdbUsername, w.ckdbPassword,
		common.ALERT_EVENT.TableName(), config.Base.CKDB.TimeZone, ckTable, w.writerConfig.QueueCount, w.writerConfig.QueueSize, w.writerConfig.BatchSize, w.writerConfig.FlushTimeout, config.Base.CKDB.Watcher)
	if err != nil {
		return nil, err
	}
	w.ckWriter = ckwriter
	w.ckWriter.Run()
	return w, nil
}
