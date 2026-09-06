package dbwriter

import (
	"github.com/ClickHouse/ch-go/proto"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
)

type ProcBlockEventBlock struct {
	EventBlock
	ColRuleID           proto.ColStr
	ColTargetType       *proto.ColLowCardinality[string]
	ColAction           *proto.ColLowCardinality[string]
	ColMechanism        *proto.ColLowCardinality[string]
	ColGuarantee        *proto.ColLowCardinality[string]
	ColErrno            proto.ColInt32
	ColPid              proto.ColUInt32
	ColParentPid        proto.ColUInt32
	ColRootPID          proto.ColUInt32
	ColUID              proto.ColUInt32
	ColGID              proto.ColUInt32
	ColCmdline          proto.ColStr
	ColExecPath         proto.ColStr
	ColSyscallName      *proto.ColLowCardinality[string]
	ColSyscallID        proto.ColUInt32
	ColPolicyEpoch      proto.ColUInt64
	ColSyscallThread    proto.ColUInt32
	ColSyscallCoroutine proto.ColUInt32
}

func (b *ProcBlockEventBlock) Reset() {
	b.EventBlock.Reset()
	b.ColRuleID.Reset()
	b.ColTargetType.Reset()
	b.ColAction.Reset()
	b.ColMechanism.Reset()
	b.ColGuarantee.Reset()
	b.ColErrno.Reset()
	b.ColPid.Reset()
	b.ColParentPid.Reset()
	b.ColRootPID.Reset()
	b.ColUID.Reset()
	b.ColGID.Reset()
	b.ColCmdline.Reset()
	b.ColExecPath.Reset()
	b.ColSyscallName.Reset()
	b.ColSyscallID.Reset()
	b.ColPolicyEpoch.Reset()
	b.ColSyscallThread.Reset()
	b.ColSyscallCoroutine.Reset()
}

func (b *ProcBlockEventBlock) ToInput(input proto.Input) proto.Input {
	input = b.EventBlock.ToInput(input)
	return append(input,
		proto.InputColumn{Name: "rule_id", Data: &b.ColRuleID},
		proto.InputColumn{Name: "target_type", Data: b.ColTargetType},
		proto.InputColumn{Name: "action", Data: b.ColAction},
		proto.InputColumn{Name: "mechanism", Data: b.ColMechanism},
		proto.InputColumn{Name: "guarantee", Data: b.ColGuarantee},
		proto.InputColumn{Name: "errno", Data: &b.ColErrno},
		proto.InputColumn{Name: "pid", Data: &b.ColPid},
		proto.InputColumn{Name: "parent_pid", Data: &b.ColParentPid},
		proto.InputColumn{Name: "root_pid", Data: &b.ColRootPID},
		proto.InputColumn{Name: "uid", Data: &b.ColUID},
		proto.InputColumn{Name: "gid", Data: &b.ColGID},
		proto.InputColumn{Name: "cmdline", Data: &b.ColCmdline},
		proto.InputColumn{Name: "exec_path", Data: &b.ColExecPath},
		proto.InputColumn{Name: "syscall_name", Data: b.ColSyscallName},
		proto.InputColumn{Name: "syscall_id", Data: &b.ColSyscallID},
		proto.InputColumn{Name: "policy_epoch", Data: &b.ColPolicyEpoch},
		proto.InputColumn{Name: "syscall_thread", Data: &b.ColSyscallThread},
		proto.InputColumn{Name: "syscall_coroutine", Data: &b.ColSyscallCoroutine},
	)
}

func (n *ProcBlockEventStore) NewColumnBlock() ckdb.CKColumnBlock {
	return &ProcBlockEventBlock{
		EventBlock:     *n.EventStore.NewColumnBlock().(*EventBlock),
		ColTargetType:  new(proto.ColStr).LowCardinality(),
		ColAction:      new(proto.ColStr).LowCardinality(),
		ColMechanism:   new(proto.ColStr).LowCardinality(),
		ColGuarantee:   new(proto.ColStr).LowCardinality(),
		ColSyscallName: new(proto.ColStr).LowCardinality(),
	}
}

func (n *ProcBlockEventStore) AppendToColumnBlock(b ckdb.CKColumnBlock) {
	block := b.(*ProcBlockEventBlock)
	n.EventStore.AppendToColumnBlock(&block.EventBlock)
	block.ColRuleID.Append(n.RuleID)
	block.ColTargetType.Append(n.TargetType)
	block.ColAction.Append(n.Action)
	block.ColMechanism.Append(n.Mechanism)
	block.ColGuarantee.Append(n.Guarantee)
	block.ColErrno.Append(n.Errno)
	block.ColPid.Append(n.Pid)
	block.ColParentPid.Append(n.ParentPid)
	block.ColRootPID.Append(n.RootPID)
	block.ColUID.Append(n.UID)
	block.ColGID.Append(n.GID)
	block.ColCmdline.Append(n.Cmdline)
	block.ColExecPath.Append(n.ExecPath)
	block.ColSyscallName.Append(n.SyscallName)
	block.ColSyscallID.Append(n.SyscallID)
	block.ColPolicyEpoch.Append(n.PolicyEpoch)
	block.ColSyscallThread.Append(n.SyscallThread)
	block.ColSyscallCoroutine.Append(n.SyscallCoroutine)
}
