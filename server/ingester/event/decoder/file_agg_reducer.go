package decoder

import (
	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
)

type FileAggReducer struct {
	pending *dbwriter.FileAggEventStore
}

func NewFileAggReducer() *FileAggReducer {
	return &FileAggReducer{}
}

func cloneRawFileEventToAgg(raw *dbwriter.EventStore) *dbwriter.FileAggEventStore {
	if raw == nil {
		return nil
	}
	agg := dbwriter.AcquireFileAggEventStore()
	agg.EventStore = *raw
	agg.StoreEventType = common.FILE_AGG_EVENT
	agg.IsFileEvent = true
	agg.EventCount = 1
	return agg
}

func sameFileAggKey(a, b *dbwriter.FileAggEventStore) bool {
	if a == nil || b == nil {
		return false
	}
	return a.VTAPID == b.VTAPID &&
		a.RootPID == b.RootPID &&
		a.GProcessID == b.GProcessID &&
		a.EventType == b.EventType &&
		a.ProcessKName == b.ProcessKName &&
		a.AppInstance == b.AppInstance &&
		a.FileDir == b.FileDir &&
		a.FileName == b.FileName &&
		a.MountSource == b.MountSource &&
		a.MountPoint == b.MountPoint &&
		a.FileType == b.FileType &&
		a.AccessPermission == b.AccessPermission &&
		a.SyscallThread == b.SyscallThread &&
		a.SyscallCoroutine == b.SyscallCoroutine
}

func (r *FileAggReducer) Add(raw *dbwriter.EventStore) *dbwriter.FileAggEventStore {
	next := cloneRawFileEventToAgg(raw)
	if next == nil {
		return nil
	}
	if r.pending == nil {
		r.pending = next
		return nil
	}
	if sameFileAggKey(r.pending, next) {
		r.pending.EventCount++
		r.pending.Bytes += next.Bytes
		r.pending.Duration += next.Duration
		if next.EndTime > r.pending.EndTime {
			r.pending.EndTime = next.EndTime
		}
		if next.Offset > r.pending.Offset {
			r.pending.Offset = next.Offset
		}
		next.Release()
		return nil
	}
	flushed := r.pending
	r.pending = next
	return flushed
}

func (r *FileAggReducer) Flush() *dbwriter.FileAggEventStore {
	if r.pending == nil {
		return nil
	}
	flushed := r.pending
	r.pending = nil
	return flushed
}
