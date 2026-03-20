package dbwriter

import (
	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type ProcPermEventBlock struct {
	EventBlock
	ColPid              proto.ColUInt32
	ColRootPID          proto.ColUInt32
	ColOldUID           proto.ColUInt32
	ColOldGID           proto.ColUInt32
	ColNewUID           proto.ColUInt32
	ColNewGID           proto.ColUInt32
	ColSyscallThread    proto.ColUInt32
	ColSyscallCoroutine proto.ColUInt32
}

func (b *ProcPermEventBlock) Reset() {
	b.EventBlock.Reset()
	b.ColPid.Reset()
	b.ColRootPID.Reset()
	b.ColOldUID.Reset()
	b.ColOldGID.Reset()
	b.ColNewUID.Reset()
	b.ColNewGID.Reset()
	b.ColSyscallThread.Reset()
	b.ColSyscallCoroutine.Reset()
}

func (b *ProcPermEventBlock) ToInput(input proto.Input) proto.Input {
	input = b.EventBlock.ToInput(input)
	return append(input,
		proto.InputColumn{Name: "pid", Data: &b.ColPid},
		proto.InputColumn{Name: "root_pid", Data: &b.ColRootPID},
		proto.InputColumn{Name: "old_uid", Data: &b.ColOldUID},
		proto.InputColumn{Name: "old_gid", Data: &b.ColOldGID},
		proto.InputColumn{Name: "new_uid", Data: &b.ColNewUID},
		proto.InputColumn{Name: "new_gid", Data: &b.ColNewGID},
		proto.InputColumn{Name: "syscall_thread", Data: &b.ColSyscallThread},
		proto.InputColumn{Name: "syscall_coroutine", Data: &b.ColSyscallCoroutine},
	)
}

func (n *ProcPermEventStore) NewColumnBlock() ckdb.CKColumnBlock {
	return &ProcPermEventBlock{
		EventBlock: *n.EventStore.NewColumnBlock().(*EventBlock),
	}
}

func (n *ProcPermEventStore) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*ProcPermEventBlock)
	n.EventStore.AppendToColumnBlock(&block.EventBlock)
	block.ColPid.Append(n.Pid)
	block.ColRootPID.Append(n.RootPID)
	block.ColOldUID.Append(n.OldUID)
	block.ColOldGID.Append(n.OldGID)
	block.ColNewUID.Append(n.NewUID)
	block.ColNewGID.Append(n.NewGID)
	block.ColSyscallThread.Append(n.SyscallThread)
	block.ColSyscallCoroutine.Append(n.SyscallCoroutine)
}
