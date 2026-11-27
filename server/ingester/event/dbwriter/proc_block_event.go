package dbwriter

import (
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

var procBlockEventPool = pool.NewLockFreePool(func() *ProcBlockEventStore {
	return &ProcBlockEventStore{
		EventStore: EventStore{
			AttributeNames:  []string{},
			AttributeValues: []string{},
			StoreEventType:  common.PROC_BLOCK_EVENT,
			IsIPv4:          true,
		},
	}
})

type ProcBlockEventStore struct {
	EventStore

	RuleID      string
	TargetType  string
	Action      string
	Mechanism   string
	Guarantee   string
	Errno       int32
	Pid         uint32
	ParentPid   uint32
	UID         uint32
	GID         uint32
	Cmdline     string
	ExecPath    string
	SyscallName string
	SyscallID   uint32
	PolicyEpoch uint64
}

func AcquireProcBlockEventStore() *ProcBlockEventStore {
	e := procBlockEventPool.Get()
	e.Reset()
	return e
}

func ReleaseProcBlockEventStore(e *ProcBlockEventStore) {
	if e == nil {
		return
	}
	attrNames := e.AttributeNames[:0]
	attrValues := e.AttributeValues[:0]
	*e = ProcBlockEventStore{}
	e.AttributeNames = attrNames
	e.AttributeValues = attrValues
	e.IsIPv4 = true
	e.StoreEventType = common.PROC_BLOCK_EVENT
	procBlockEventPool.Put(e)
}

func (e *ProcBlockEventStore) Release() {
	ReleaseProcBlockEventStore(e)
}

func ProcBlockEventColumns() []*ckdb.Column {
	columns := EventColumns(false)
	columns = append(columns,
		ckdb.NewColumn("rule_id", ckdb.String).SetGroupBy(),
		ckdb.NewColumn("target_type", ckdb.LowCardinalityString).SetGroupBy(),
		ckdb.NewColumn("action", ckdb.LowCardinalityString).SetGroupBy(),
		ckdb.NewColumn("mechanism", ckdb.LowCardinalityString).SetGroupBy(),
		ckdb.NewColumn("guarantee", ckdb.LowCardinalityString).SetGroupBy(),
		ckdb.NewColumn("errno", ckdb.Int32).SetGroupBy(),
		ckdb.NewColumn("pid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("parent_pid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("root_pid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("uid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("gid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("cmdline", ckdb.String).SetIgnoredInAggrTable(),
		ckdb.NewColumn("exec_path", ckdb.String).SetIgnoredInAggrTable(),
		ckdb.NewColumn("syscall_name", ckdb.LowCardinalityString).SetGroupBy(),
		ckdb.NewColumn("syscall_id", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("policy_epoch", ckdb.UInt64).SetGroupBy(),
		ckdb.NewColumn("syscall_thread", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("syscall_coroutine", ckdb.UInt32).SetGroupBy(),
	)
	return columns
}
