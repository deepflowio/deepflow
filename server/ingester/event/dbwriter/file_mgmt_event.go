package dbwriter

import (
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

var fileMgmtEventPool = pool.NewLockFreePool(func() *FileMgmtEventStore {
	return &FileMgmtEventStore{
		EventStore: EventStore{
			AttributeNames:  []string{},
			AttributeValues: []string{},
			StoreEventType:  common.FILE_MGMT_EVENT,
			IsFileEvent:     true,
			IsIPv4:          true,
		},
	}
})

type FileMgmtEventStore struct {
	EventStore

	TargetUID  uint32
	TargetGID  uint32
	TargetMode uint32
}

func AcquireFileMgmtEventStore() *FileMgmtEventStore {
	e := fileMgmtEventPool.Get()
	e.Reset()
	return e
}

func ReleaseFileMgmtEventStore(e *FileMgmtEventStore) {
	if e == nil {
		return
	}
	attrNames := e.AttributeNames[:0]
	attrValues := e.AttributeValues[:0]
	*e = FileMgmtEventStore{}
	e.AttributeNames = attrNames
	e.AttributeValues = attrValues
	e.IsIPv4 = true
	e.IsFileEvent = true
	e.StoreEventType = common.FILE_MGMT_EVENT
	fileMgmtEventPool.Put(e)
}

func (e *FileMgmtEventStore) Release() {
	ReleaseFileMgmtEventStore(e)
}

func FileMgmtEventColumns() []*ckdb.Column {
	columns := EventColumns(true)
	columns = append(columns,
		ckdb.NewColumn("root_pid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("target_uid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("target_gid", ckdb.UInt32).SetGroupBy(),
		ckdb.NewColumn("target_mode", ckdb.UInt32).SetGroupBy(),
	)
	return columns
}
