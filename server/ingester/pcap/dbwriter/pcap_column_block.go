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
	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type PcapStoreBlock struct {
	ColTime        proto.ColDateTime
	ColStartTime   proto.ColDateTime64
	ColEndTime     proto.ColDateTime64
	ColFlowId      proto.ColUInt64
	ColAgentId     proto.ColUInt16
	ColPacketCount proto.ColUInt32
	ColPacketBatch proto.ColStr
	ColAclGids     *proto.ColArr[uint16]
	ColTeamId      proto.ColUInt16
}

func (b *PcapStoreBlock) Reset() {
	b.ColTime.Reset()
	b.ColStartTime.Reset()
	b.ColEndTime.Reset()
	b.ColFlowId.Reset()
	b.ColAgentId.Reset()
	b.ColPacketCount.Reset()
	b.ColPacketBatch.Reset()
	b.ColAclGids.Reset()
	b.ColTeamId.Reset()
}

func (b *PcapStoreBlock) ToInput(input proto.Input) proto.Input {
	return append(input,
		proto.InputColumn{Name: ckdb.COLUMN_TIME, Data: &b.ColTime},
		proto.InputColumn{Name: ckdb.COLUMN_START_TIME, Data: &b.ColStartTime},
		proto.InputColumn{Name: ckdb.COLUMN_END_TIME, Data: &b.ColEndTime},
		proto.InputColumn{Name: ckdb.COLUMN_FLOW_ID, Data: &b.ColFlowId},
		proto.InputColumn{Name: ckdb.COLUMN_AGENT_ID, Data: &b.ColAgentId},
		proto.InputColumn{Name: ckdb.COLUMN_PACKET_COUNT, Data: &b.ColPacketCount},
		proto.InputColumn{Name: ckdb.COLUMN_PACKET_BATCH, Data: &b.ColPacketBatch},
		proto.InputColumn{Name: ckdb.COLUMN_ACL_GIDS, Data: b.ColAclGids},
		proto.InputColumn{Name: ckdb.COLUMN_TEAM_ID, Data: &b.ColTeamId},
	)
}

func (n *PcapStore) NewColumnBlock() ckdb.CKColumnBlock {
	return &PcapStoreBlock{
		ColAclGids: new(proto.ColUInt16).Array(),
	}
}

func (n *PcapStore) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*PcapStoreBlock)
	ckdb.AppendColDateTime(&block.ColTime, n.Time)
	ckdb.AppendColDateTime64Micro(&block.ColStartTime, n.StartTime)
	ckdb.AppendColDateTime64Micro(&block.ColEndTime, n.EndTime)
	block.ColFlowId.Append(n.FlowID)
	block.ColAgentId.Append(n.VtapID)
	block.ColPacketCount.Append(n.PacketCount)
	block.ColPacketBatch.AppendBytes(n.PacketBatch)
	block.ColAclGids.Append(n.AclGids)
	block.ColTeamId.Append(n.TeamID)
}
