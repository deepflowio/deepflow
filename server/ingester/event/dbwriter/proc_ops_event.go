package dbwriter

import (
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

var procOpsEventPool = pool.NewLockFreePool(func() *ProcOpsEventStore {
	return &ProcOpsEventStore{
		EventStore: EventStore{
			AttributeNames:  []string{},
			AttributeValues: []string{},
			StoreEventType:  common.PROC_OPS_EVENT,
		},
	}
})

type ProcOpsEventStore struct {
	EventStore

	Pid            uint32
	ParentPid      uint32
	AiAgentRootPid uint32
	UID            uint32
	GID            uint32
	Cmdline        string
	ExecPath       string
}

func AcquireProcOpsEventStore() *ProcOpsEventStore {
	e := procOpsEventPool.Get()
	e.Reset()
	return e
}

func ReleaseProcOpsEventStore(e *ProcOpsEventStore) {
	if e == nil {
		return
	}
	attrNames := e.AttributeNames[:0]
	attrValues := e.AttributeValues[:0]
	*e = ProcOpsEventStore{}
	e.AttributeNames = attrNames
	e.AttributeValues = attrValues
	e.IsIPv4 = true
	e.StoreEventType = common.PROC_OPS_EVENT
	procOpsEventPool.Put(e)
}

func (e *ProcOpsEventStore) Release() {
	ReleaseProcOpsEventStore(e)
}

func ProcOpsEventColumns() []*ckdb.Column {
	columns := EventColumns(false)
	columns = append(columns,
		ckdb.NewColumn("pid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("parent_pid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("ai_agent_root_pid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("uid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("gid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("cmdline", ckdb.String).SetIgnoredInAggrTable(),
		ckdb.NewColumn("exec_path", ckdb.String).SetIgnoredInAggrTable(),
		ckdb.NewColumn("syscall_thread", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("syscall_coroutine", ckdb.UInt32).SetGroupBy(),
	)
	return columns
}
