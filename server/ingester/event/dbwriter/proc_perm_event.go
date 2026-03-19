package dbwriter

import (
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

var procPermEventPool = pool.NewLockFreePool(func() *ProcPermEventStore {
	return &ProcPermEventStore{
		EventStore: EventStore{
			AttributeNames:  []string{},
			AttributeValues: []string{},
			StoreEventType:  common.PROC_PERM_EVENT,
		},
	}
})

type ProcPermEventStore struct {
	EventStore

	Pid            uint32
	AiAgentRootPid uint32
	OldUID         uint32
	OldGID         uint32
	NewUID         uint32
	NewGID         uint32
}

func AcquireProcPermEventStore() *ProcPermEventStore {
	e := procPermEventPool.Get()
	e.Reset()
	return e
}

func ReleaseProcPermEventStore(e *ProcPermEventStore) {
	if e == nil {
		return
	}
	attrNames := e.AttributeNames[:0]
	attrValues := e.AttributeValues[:0]
	*e = ProcPermEventStore{}
	e.AttributeNames = attrNames
	e.AttributeValues = attrValues
	e.IsIPv4 = true
	e.StoreEventType = common.PROC_PERM_EVENT
	procPermEventPool.Put(e)
}

func (e *ProcPermEventStore) Release() {
	ReleaseProcPermEventStore(e)
}

func ProcPermEventColumns() []*ckdb.Column {
	columns := EventColumns(false)
	columns = append(columns,
		ckdb.NewColumn("pid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("ai_agent_root_pid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("old_uid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("old_gid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("new_uid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("new_gid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("syscall_thread", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("syscall_coroutine", ckdb.UInt32).SetGroupBy(),
	)
	return columns
}
