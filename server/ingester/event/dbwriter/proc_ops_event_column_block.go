package dbwriter

import (
	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type ProcOpsEventBlock struct {
	EventBlock
	ColPid              proto.ColUInt32
	ColParentPid        proto.ColUInt32
	ColAiAgentRootPid   proto.ColUInt32
	ColUID              proto.ColUInt32
	ColGID              proto.ColUInt32
	ColCmdline          proto.ColStr
	ColExecPath         proto.ColStr
	ColSyscallThread    proto.ColUInt32
	ColSyscallCoroutine proto.ColUInt32
}

func (b *ProcOpsEventBlock) Reset() {
	b.EventBlock.Reset()
	b.ColPid.Reset()
	b.ColParentPid.Reset()
	b.ColAiAgentRootPid.Reset()
	b.ColUID.Reset()
	b.ColGID.Reset()
	b.ColCmdline.Reset()
	b.ColExecPath.Reset()
	b.ColSyscallThread.Reset()
	b.ColSyscallCoroutine.Reset()
}

func (b *ProcOpsEventBlock) ToInput(input proto.Input) proto.Input {
	input = b.EventBlock.ToInput(input)
	return append(input,
		proto.InputColumn{Name: "pid", Data: &b.ColPid},
		proto.InputColumn{Name: "parent_pid", Data: &b.ColParentPid},
		proto.InputColumn{Name: "ai_agent_root_pid", Data: &b.ColAiAgentRootPid},
		proto.InputColumn{Name: "uid", Data: &b.ColUID},
		proto.InputColumn{Name: "gid", Data: &b.ColGID},
		proto.InputColumn{Name: "cmdline", Data: &b.ColCmdline},
		proto.InputColumn{Name: "exec_path", Data: &b.ColExecPath},
		proto.InputColumn{Name: "syscall_thread", Data: &b.ColSyscallThread},
		proto.InputColumn{Name: "syscall_coroutine", Data: &b.ColSyscallCoroutine},
	)
}

func (n *ProcOpsEventStore) NewColumnBlock() ckdb.CKColumnBlock {
	return &ProcOpsEventBlock{
		EventBlock: *n.EventStore.NewColumnBlock().(*EventBlock),
	}
}

func (n *ProcOpsEventStore) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*ProcOpsEventBlock)
	n.EventStore.AppendToColumnBlock(&block.EventBlock)
	block.ColPid.Append(n.Pid)
	block.ColParentPid.Append(n.ParentPid)
	block.ColAiAgentRootPid.Append(n.AiAgentRootPid)
	block.ColUID.Append(n.UID)
	block.ColGID.Append(n.GID)
	block.ColCmdline.Append(n.Cmdline)
	block.ColExecPath.Append(n.ExecPath)
	block.ColSyscallThread.Append(n.SyscallThread)
	block.ColSyscallCoroutine.Append(n.SyscallCoroutine)
}
