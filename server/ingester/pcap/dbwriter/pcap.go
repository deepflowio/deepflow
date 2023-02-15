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
	"fmt"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

const (
	DefaultPcapPartition = ckdb.TimeFuncFourHour
)

type PcapStore struct {
	Time      uint32
	EndTime   int64
	FlowID    uint64
	VtapID    uint16
	PcapCount uint32
	PcapBatch []byte
}

func PcapStoreColumns() []*ckdb.Column {
	return []*ckdb.Column{
		ckdb.NewColumn("time", ckdb.DateTime).SetComment("精度: 秒"),
		ckdb.NewColumn("end_time", ckdb.DateTime64us).SetComment("精度: 微秒"),
		ckdb.NewColumn("flow_id", ckdb.UInt64).SetIndex(ckdb.IndexMinmax),
		ckdb.NewColumn("vtap_id", ckdb.UInt16).SetIndex(ckdb.IndexSet),
		ckdb.NewColumn("pcap_count", ckdb.UInt32).SetIndex(ckdb.IndexNone),
		ckdb.NewColumn("pcap_batch", ckdb.String).SetIndex(ckdb.IndexNone).SetComment("data format reference: https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html"),
	}
}

func (s *PcapStore) WriteBlock(block *ckdb.Block) {
	block.WriteDateTime(s.Time)
	block.Write(
		s.EndTime,
		s.FlowID,
		s.VtapID,
		s.PcapCount,
		utils.String(s.PcapBatch))
}

func (p *PcapStore) Release() {
	ReleasePcapStore(p)
}

func (p *PcapStore) String() string {
	return fmt.Sprintf("PcapStore: %+v\n", *p)
}

var poolPcapStore = pool.NewLockFreePool(func() interface{} {
	return new(PcapStore)
})

func AcquirePcapStore() *PcapStore {
	l := poolPcapStore.Get().(*PcapStore)
	return l
}

func ReleasePcapStore(l *PcapStore) {
	if l == nil {
		return
	}
	t := l.PcapBatch[:0]
	*l = PcapStore{}
	l.PcapBatch = t
	poolPcapStore.Put(l)
}

func GenPcapCKTable(cluster, storagePolicy string, ttl int, coldStorage *ckdb.ColdStorage) *ckdb.Table {
	timeKey := "time"
	engine := ckdb.MergeTree
	orderKeys := []string{"flow_id", "vtap_id", timeKey}

	return &ckdb.Table{
		Version:         common.CK_VERSION,
		Database:        PCAP_DB,
		LocalName:       PCAP_TABLE + ckdb.LOCAL_SUBFFIX,
		GlobalName:      PCAP_TABLE,
		Columns:         PcapStoreColumns(),
		TimeKey:         timeKey,
		TTL:             ttl,
		PartitionFunc:   DefaultPcapPartition,
		Engine:          engine,
		Cluster:         cluster,
		StoragePolicy:   storagePolicy,
		ColdStorage:     *coldStorage,
		OrderKeys:       orderKeys,
		PrimaryKeyCount: len(orderKeys),
	}
}
