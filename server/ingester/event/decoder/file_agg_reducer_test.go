package decoder

import (
	"testing"

	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
)

func makeRawFileEvent(processKName, eventType, fileName string, bytes uint32) *dbwriter.EventStore {
	e := dbwriter.AcquireEventStore()
	e.StoreEventType = common.FILE_EVENT
	e.IsFileEvent = true
	e.ProcessKName = processKName
	e.EventType = eventType
	e.FileDir = "/tmp/"
	e.FileName = fileName
	e.Bytes = bytes
	e.Duration = 10
	e.SyscallThread = 1
	e.SyscallCoroutine = 0
	e.FileType = 1
	e.MountSource = "/dev/root"
	e.MountPoint = "/"
	e.AccessPermission = 420
	e.AppInstance = "1234"
	e.Time = 100
	e.StartTime = 1000
	e.EndTime = 1010
	return e
}

func TestFileAggReducerMergesConsecutiveSameKey(t *testing.T) {
	reducer := NewFileAggReducer()
	first := makeRawFileEvent("codex", "read", "tls-ca-bundle.pem", 1024)
	second := makeRawFileEvent("codex", "read", "tls-ca-bundle.pem", 1024)

	if flushed := reducer.Add(first); flushed != nil {
		t.Fatalf("unexpected flush on first event")
	}
	if flushed := reducer.Add(second); flushed != nil {
		t.Fatalf("unexpected flush on consecutive same-key event")
	}

	merged := reducer.Flush()
	if merged == nil {
		t.Fatalf("expected merged aggregate on flush")
	}
	if merged.EventCount != 2 {
		t.Fatalf("event count = %d, want 2", merged.EventCount)
	}
	if merged.Bytes != 2048 {
		t.Fatalf("bytes = %d, want 2048", merged.Bytes)
	}
}

func TestFileAggReducerFlushesOnKeyChange(t *testing.T) {
	reducer := NewFileAggReducer()
	first := makeRawFileEvent("codex", "read", "tls-ca-bundle.pem", 1024)
	second := makeRawFileEvent("codex", "write", "codex-tui.log", 256)

	if flushed := reducer.Add(first); flushed != nil {
		t.Fatalf("unexpected flush on first event")
	}
	flushed := reducer.Add(second)
	if flushed == nil {
		t.Fatalf("expected flush when aggregation key changes")
	}
	if flushed.FileName != "tls-ca-bundle.pem" {
		t.Fatalf("flushed file = %q, want tls-ca-bundle.pem", flushed.FileName)
	}
	if flushed.EventCount != 1 {
		t.Fatalf("flushed event count = %d, want 1", flushed.EventCount)
	}

	last := reducer.Flush()
	if last == nil || last.FileName != "codex-tui.log" {
		t.Fatalf("expected pending aggregate for codex-tui.log, got %+v", last)
	}
}
