package dbwriter

import (
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/libs/ckdb"
	"github.com/deepflowio/deepflow/server/libs/pool"
)

var fileAggEventPool = pool.NewLockFreePool(func() *FileAggEventStore {
	return &FileAggEventStore{
		EventStore: EventStore{
			AttributeNames:  []string{},
			AttributeValues: []string{},
			StoreEventType:  common.FILE_AGG_EVENT,
			IsFileEvent:     true,
		},
	}
})

type FileAggEventStore struct {
	EventStore

	EventCount uint32
}

func AcquireFileAggEventStore() *FileAggEventStore {
	e := fileAggEventPool.Get()
	e.Reset()
	return e
}

func ReleaseFileAggEventStore(e *FileAggEventStore) {
	if e == nil {
		return
	}
	attrNames := e.AttributeNames[:0]
	attrValues := e.AttributeValues[:0]
	*e = FileAggEventStore{}
	e.AttributeNames = attrNames
	e.AttributeValues = attrValues
	e.IsIPv4 = true
	e.IsFileEvent = true
	e.StoreEventType = common.FILE_AGG_EVENT
	fileAggEventPool.Put(e)
}

func (e *FileAggEventStore) Release() {
	ReleaseFileAggEventStore(e)
}

func FileAggEventColumns() []*ckdb.Column {
	columns := EventColumns(true)
	columns = append(columns, ckdb.NewColumn("event_count", ckdb.UInt32).SetAggrSum().SetAggrSum())
	return columns
}
