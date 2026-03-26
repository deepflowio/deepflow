package decoder

import (
	"time"

	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
)

const fileAggIdleGap = int64(100 * time.Millisecond / time.Microsecond)

type fileAggKey struct {
	vtapID           uint16
	rootPID          uint32
	gprocessID       uint32
	eventType        string
	processKName     string
	appInstance      string
	fileDir          string
	fileName         string
	mountSource      string
	mountPoint       string
	fileType         uint8
	accessPermission uint32
	syscallThread    uint32
	syscallCoroutine uint32
}

type fileAggFileKey struct {
	vtapID   uint16
	rootPID  uint32
	fileDir  string
	fileName string
}

type FileAggReducer struct {
	pending map[fileAggKey]*dbwriter.FileAggEventStore
	order   []fileAggKey
}

func NewFileAggReducer() *FileAggReducer {
	return &FileAggReducer{
		pending: make(map[fileAggKey]*dbwriter.FileAggEventStore),
	}
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

func newFileAggKey(e *dbwriter.FileAggEventStore) fileAggKey {
	return fileAggKey{
		vtapID:           e.VTAPID,
		rootPID:          e.RootPID,
		gprocessID:       e.GProcessID,
		eventType:        e.EventType,
		processKName:     e.ProcessKName,
		appInstance:      e.AppInstance,
		fileDir:          e.FileDir,
		fileName:         e.FileName,
		mountSource:      e.MountSource,
		mountPoint:       e.MountPoint,
		fileType:         e.FileType,
		accessPermission: e.AccessPermission,
		syscallThread:    e.SyscallThread,
		syscallCoroutine: e.SyscallCoroutine,
	}
}

func newFileAggFileKey(vtapID uint16, rootPID uint32, fileDir, fileName string) fileAggFileKey {
	return fileAggFileKey{
		vtapID:   vtapID,
		rootPID:  rootPID,
		fileDir:  fileDir,
		fileName: fileName,
	}
}

func newFileAggFileKeyFromEvent(e *dbwriter.FileAggEventStore) fileAggFileKey {
	return newFileAggFileKey(e.VTAPID, e.RootPID, e.FileDir, e.FileName)
}

func (r *FileAggReducer) removeOrderKey(target fileAggKey) {
	if len(r.order) == 0 {
		return
	}
	next := r.order[:0]
	for _, key := range r.order {
		if key == target {
			continue
		}
		next = append(next, key)
	}
	r.order = next
}

func shouldSplitFileAggByIdleGap(current, next *dbwriter.FileAggEventStore) bool {
	if current == nil || next == nil {
		return false
	}
	if current.EndTime <= 0 || next.StartTime <= 0 || next.StartTime <= current.EndTime {
		return false
	}
	return next.StartTime-current.EndTime > fileAggIdleGap
}

func (r *FileAggReducer) Add(raw *dbwriter.EventStore) []*dbwriter.FileAggEventStore {
	next := cloneRawFileEventToAgg(raw)
	if next == nil {
		return nil
	}
	key := newFileAggKey(next)
	if current, ok := r.pending[key]; ok {
		if shouldSplitFileAggByIdleGap(current, next) {
			delete(r.pending, key)
			r.removeOrderKey(key)
			r.pending[key] = next
			r.order = append(r.order, key)
			return []*dbwriter.FileAggEventStore{current}
		}
		current.EventCount++
		current.Bytes += next.Bytes
		current.Duration += next.Duration
		if next.EndTime > current.EndTime {
			current.EndTime = next.EndTime
		}
		if next.Offset > current.Offset {
			current.Offset = next.Offset
		}
		next.Release()
		return nil
	}
	r.pending[key] = next
	r.order = append(r.order, key)
	return nil
}

func (r *FileAggReducer) FlushFile(vtapID uint16, rootPID uint32, fileDir, fileName string) []*dbwriter.FileAggEventStore {
	if len(r.order) == 0 {
		return nil
	}
	target := newFileAggFileKey(vtapID, rootPID, fileDir, fileName)
	var flushed []*dbwriter.FileAggEventStore
	for _, key := range r.order {
		item, ok := r.pending[key]
		if !ok {
			continue
		}
		if newFileAggFileKeyFromEvent(item) != target {
			continue
		}
		flushed = append(flushed, item)
		delete(r.pending, key)
		r.removeOrderKey(key)
	}
	return flushed
}

func (r *FileAggReducer) Flush() []*dbwriter.FileAggEventStore {
	if len(r.order) == 0 {
		return nil
	}
	flushed := make([]*dbwriter.FileAggEventStore, 0, len(r.order))
	for _, key := range r.order {
		if item, ok := r.pending[key]; ok {
			flushed = append(flushed, item)
		}
	}
	r.pending = make(map[fileAggKey]*dbwriter.FileAggEventStore)
	r.order = r.order[:0]
	return flushed
}
