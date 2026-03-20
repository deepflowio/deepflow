package decoder

import (
	"fmt"

	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
)

type FileMgmtReducer struct {
	created map[string]struct{}
}

func NewFileMgmtReducer() *FileMgmtReducer {
	return &FileMgmtReducer{created: make(map[string]struct{})}
}

func (r *FileMgmtReducer) key(e *dbwriter.FileMgmtEventStore) string {
	return fmt.Sprintf("%d|%d|%s|%s|%s|%s",
		e.VTAPID, e.RootPID, e.MountSource, e.MountPoint, e.FileDir, e.FileName,
	)
}

func (r *FileMgmtReducer) Add(e *dbwriter.FileMgmtEventStore) *dbwriter.FileMgmtEventStore {
	if e == nil {
		return nil
	}
	key := r.key(e)
	switch e.EventType {
	case "create":
		if _, ok := r.created[key]; ok {
			return nil
		}
		r.created[key] = struct{}{}
		return e
	case "delete":
		delete(r.created, key)
		return e
	default:
		return e
	}
}
