package dbwriter

import (
	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type FileMgmtEventBlock struct {
	EventBlock
	ColRootPID    proto.ColUInt32
	ColTargetUID  proto.ColUInt32
	ColTargetGID  proto.ColUInt32
	ColTargetMode proto.ColUInt32
}

func (b *FileMgmtEventBlock) Reset() {
	b.EventBlock.Reset()
	b.ColRootPID.Reset()
	b.ColTargetUID.Reset()
	b.ColTargetGID.Reset()
	b.ColTargetMode.Reset()
}

func (b *FileMgmtEventBlock) ToInput(input proto.Input) proto.Input {
	input = b.EventBlock.ToInput(input)
	return append(input,
		proto.InputColumn{Name: "root_pid", Data: &b.ColRootPID},
		proto.InputColumn{Name: "target_uid", Data: &b.ColTargetUID},
		proto.InputColumn{Name: "target_gid", Data: &b.ColTargetGID},
		proto.InputColumn{Name: "target_mode", Data: &b.ColTargetMode},
	)
}

func (n *FileMgmtEventStore) NewColumnBlock() ckdb.CKColumnBlock {
	block := n.EventStore.NewColumnBlock().(*EventBlock)
	return &FileMgmtEventBlock{EventBlock: *block}
}

func (n *FileMgmtEventStore) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*FileMgmtEventBlock)
	n.EventStore.AppendToColumnBlock(&block.EventBlock)
	block.ColRootPID.Append(n.RootPID)
	block.ColTargetUID.Append(n.TargetUID)
	block.ColTargetGID.Append(n.TargetGID)
	block.ColTargetMode.Append(n.TargetMode)
}
