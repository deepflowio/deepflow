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
	e.VTAPID = 1
	e.RootPID = 42
	e.GProcessID = 100
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

func makeTimedRawFileEvent(processKName, eventType, fileName string, bytes uint32, startTime, endTime int64) *dbwriter.EventStore {
	e := makeRawFileEvent(processKName, eventType, fileName, bytes)
	e.StartTime = startTime
	e.EndTime = endTime
	e.Duration = uint64(endTime - startTime)
	e.Time = uint32(startTime / 1000000)
	return e
}

func TestFileAggReducerMergesConsecutiveSameKey(t *testing.T) {
	reducer := NewFileAggReducer()
	first := makeRawFileEvent("codex", "read", "tls-ca-bundle.pem", 1024)
	second := makeRawFileEvent("codex", "read", "tls-ca-bundle.pem", 1024)

	reducer.Add(first)
	reducer.Add(second)

	flushed := reducer.Flush()
	if len(flushed) != 1 {
		t.Fatalf("flush len = %d, want 1", len(flushed))
	}
	merged := flushed[0]
	if merged.EventCount != 2 {
		t.Fatalf("event count = %d, want 2", merged.EventCount)
	}
	if merged.Bytes != 2048 {
		t.Fatalf("bytes = %d, want 2048", merged.Bytes)
	}
}

func TestFileAggReducerMergesSameKeyAcrossInterleavingEventsWithinWindow(t *testing.T) {
	reducer := NewFileAggReducer()
	a1 := makeRawFileEvent("codex", "write", "logs_1.sqlite", 4096)
	b1 := makeRawFileEvent("codex", "read", "logs_1.sqlite-wal", 4096)
	a2 := makeRawFileEvent("codex", "write", "logs_1.sqlite", 4096)
	b2 := makeRawFileEvent("codex", "read", "logs_1.sqlite-wal", 4096)

	reducer.Add(a1)
	reducer.Add(b1)
	reducer.Add(a2)
	reducer.Add(b2)

	flushed := reducer.Flush()
	if len(flushed) != 2 {
		t.Fatalf("flush len = %d, want 2", len(flushed))
	}

	if flushed[0].FileName != "logs_1.sqlite" {
		t.Fatalf("first flushed file = %q, want logs_1.sqlite", flushed[0].FileName)
	}
	if flushed[0].EventType != "write" {
		t.Fatalf("first flushed event_type = %q, want write", flushed[0].EventType)
	}
	if flushed[0].EventCount != 2 {
		t.Fatalf("first flushed event_count = %d, want 2", flushed[0].EventCount)
	}
	if flushed[0].Bytes != 8192 {
		t.Fatalf("first flushed bytes = %d, want 8192", flushed[0].Bytes)
	}

	if flushed[1].FileName != "logs_1.sqlite-wal" {
		t.Fatalf("second flushed file = %q, want logs_1.sqlite-wal", flushed[1].FileName)
	}
	if flushed[1].EventType != "read" {
		t.Fatalf("second flushed event_type = %q, want read", flushed[1].EventType)
	}
	if flushed[1].EventCount != 2 {
		t.Fatalf("second flushed event_count = %d, want 2", flushed[1].EventCount)
	}
}

func TestFileAggReducerFlushesOnDifferentGProcessID(t *testing.T) {
	reducer := NewFileAggReducer()
	first := makeRawFileEvent("codex", "write", "same.txt", 8)
	second := makeRawFileEvent("codex", "write", "same.txt", 8)
	second.GProcessID = 200

	reducer.Add(first)
	reducer.Add(second)

	flushed := reducer.Flush()
	if len(flushed) != 2 {
		t.Fatalf("flush len = %d, want 2", len(flushed))
	}
	if flushed[0].GProcessID != 100 {
		t.Fatalf("first flushed gprocess_id = %d, want 100", flushed[0].GProcessID)
	}
	if flushed[1].GProcessID != 200 {
		t.Fatalf("second flushed gprocess_id = %d, want 200", flushed[1].GProcessID)
	}
}

func TestFileAggReducerFlushesOnDifferentAgentID(t *testing.T) {
	reducer := NewFileAggReducer()
	first := makeRawFileEvent("codex", "write", "same.txt", 8)
	second := makeRawFileEvent("codex", "write", "same.txt", 8)
	second.VTAPID = 2

	reducer.Add(first)
	reducer.Add(second)

	flushed := reducer.Flush()
	if len(flushed) != 2 {
		t.Fatalf("flush len = %d, want 2", len(flushed))
	}
	if flushed[0].VTAPID != 1 {
		t.Fatalf("first flushed agent_id = %d, want 1", flushed[0].VTAPID)
	}
	if flushed[1].VTAPID != 2 {
		t.Fatalf("second flushed agent_id = %d, want 2", flushed[1].VTAPID)
	}
}

func TestFileAggReducerFlushesOnlySameFileOnMgmtBoundary(t *testing.T) {
	reducer := NewFileAggReducer()
	sameFile := makeRawFileEvent("codex", "write", "same.txt", 8)
	otherFile := makeRawFileEvent("codex", "write", "other.txt", 16)
	otherFile.StartTime = 1020
	otherFile.EndTime = 1030

	reducer.Add(sameFile)
	reducer.Add(otherFile)

	flushed := reducer.FlushFile(1, 42, "/tmp/", "same.txt")
	if len(flushed) != 1 {
		t.Fatalf("flush len = %d, want 1", len(flushed))
	}
	if flushed[0].FileName != "same.txt" {
		t.Fatalf("flushed file = %q, want same.txt", flushed[0].FileName)
	}

	remaining := reducer.Flush()
	if len(remaining) != 1 {
		t.Fatalf("remaining len = %d, want 1", len(remaining))
	}
	if remaining[0].FileName != "other.txt" {
		t.Fatalf("remaining file = %q, want other.txt", remaining[0].FileName)
	}
}

func TestFileAggReducerFlushFileFlushesAllMatchingEntries(t *testing.T) {
	reducer := NewFileAggReducer()
	writeSame := makeRawFileEvent("codex", "write", "same.txt", 8)
	readSame := makeRawFileEvent("codex", "read", "same.txt", 16)
	readSame.EventType = "read"
	readSame.StartTime = 1020
	readSame.EndTime = 1030
	otherFile := makeRawFileEvent("codex", "write", "other.txt", 4)
	otherFile.StartTime = 1040
	otherFile.EndTime = 1050

	reducer.Add(writeSame)
	reducer.Add(readSame)
	reducer.Add(otherFile)

	flushed := reducer.FlushFile(1, 42, "/tmp/", "same.txt")
	if len(flushed) != 2 {
		t.Fatalf("flush len = %d, want 2", len(flushed))
	}

	remaining := reducer.Flush()
	if len(remaining) != 1 {
		t.Fatalf("remaining len = %d, want 1", len(remaining))
	}
	if remaining[0].FileName != "other.txt" {
		t.Fatalf("remaining file = %q, want other.txt", remaining[0].FileName)
	}
}

func TestFileAggReducerSplitsSameKeyWhenIdleGapExceeded(t *testing.T) {
	reducer := NewFileAggReducer()
	first := makeTimedRawFileEvent("codex", "write", "same.txt", 8, 1000, 1010)
	second := makeTimedRawFileEvent("codex", "write", "same.txt", 8, 200000, 200010)

	reducer.Add(first)
	flushed := reducer.Add(second)
	if len(flushed) != 1 {
		t.Fatalf("add flush len = %d, want 1", len(flushed))
	}
	if flushed[0].EventCount != 1 {
		t.Fatalf("flushed event_count = %d, want 1", flushed[0].EventCount)
	}

	remaining := reducer.Flush()
	if len(remaining) != 1 {
		t.Fatalf("remaining len = %d, want 1", len(remaining))
	}
	if remaining[0].EventCount != 1 {
		t.Fatalf("remaining event_count = %d, want 1", remaining[0].EventCount)
	}
}

func TestFileAggReducerSkipsNonAiAgentEvent(t *testing.T) {
	reducer := NewFileAggReducer()
	raw := makeRawFileEvent("bash", "read", "plain.txt", 16)
	raw.RootPID = 0

	flushed := reducer.Add(raw)
	if flushed != nil {
		t.Fatalf("add returned %d flushed items, want nil", len(flushed))
	}

	remaining := reducer.Flush()
	if remaining != nil {
		t.Fatalf("flush returned %d items, want nil", len(remaining))
	}
}
