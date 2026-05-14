package dbwriter

import (
	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type FileAggEventBlock struct {
	EventBlock
	ColRootPID    proto.ColUInt32
	ColEventCount proto.ColUInt32
}

func (b *FileAggEventBlock) Reset() {
	b.EventBlock.Reset()
	b.ColRootPID.Reset()
	b.ColEventCount.Reset()
}

func (b *FileAggEventBlock) ToInput(input proto.Input) proto.Input {
	input = b.EventBlock.ToInput(input)
	return append(input,
		proto.InputColumn{Name: "root_pid", Data: &b.ColRootPID},
		proto.InputColumn{Name: "event_count", Data: &b.ColEventCount},
	)
}

func (n *FileAggEventStore) NewColumnBlock() ckdb.CKColumnBlock {
	block := n.EventStore.NewColumnBlock().(*EventBlock)
	return &FileAggEventBlock{EventBlock: *block}
}

func (n *FileAggEventStore) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*FileAggEventBlock)
	n.EventStore.AppendToColumnBlock(&block.EventBlock)
	block.ColRootPID.Append(n.RootPID)
	block.ColEventCount.Append(n.EventCount)
}
