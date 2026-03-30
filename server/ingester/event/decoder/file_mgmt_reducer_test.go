package decoder

import (
	"testing"

	"github.com/deepflowio/deepflow/server/ingester/event/dbwriter"
)

func makeFileMgmtEvent(processKName, eventType, fileName string) *dbwriter.FileMgmtEventStore {
	e := dbwriter.AcquireFileMgmtEventStore()
	e.VTAPID = 1
	e.ProcessKName = processKName
	e.EventType = eventType
	e.FileDir = "/tmp/"
	e.FileName = fileName
	e.MountSource = "/dev/root"
	e.MountPoint = "/"
	e.SyscallThread = 1
	e.SyscallCoroutine = 0
	e.RootPID = 42
	return e
}

func TestFileMgmtReducerSuppressesDuplicateCreateUntilDelete(t *testing.T) {
	reducer := NewFileMgmtReducer()
	first := makeFileMgmtEvent("bash", "create", "dup.txt")
	second := makeFileMgmtEvent("bash", "create", "dup.txt")
	deleteEvent := makeFileMgmtEvent("rm", "delete", "dup.txt")

	if out := reducer.Add(first); out == nil {
		t.Fatalf("first create should pass through")
	} else {
		out.Release()
	}

	if out := reducer.Add(second); out != nil {
		t.Fatalf("duplicate create should be suppressed")
	}

	if out := reducer.Add(deleteEvent); out == nil {
		t.Fatalf("delete should pass through and clear suppression state")
	} else {
		out.Release()
	}

	third := makeFileMgmtEvent("bash", "create", "dup.txt")
	if out := reducer.Add(third); out == nil {
		t.Fatalf("create after delete should pass through again")
	} else {
		out.Release()
	}
}

func TestFileMgmtReducerKeepsDifferentAgentCreatesSeparate(t *testing.T) {
	reducer := NewFileMgmtReducer()
	first := makeFileMgmtEvent("bash", "create", "dup.txt")
	second := makeFileMgmtEvent("bash", "create", "dup.txt")
	second.VTAPID = 2

	if out := reducer.Add(first); out == nil {
		t.Fatalf("first create should pass through")
	} else {
		out.Release()
	}

	if out := reducer.Add(second); out == nil {
		t.Fatalf("create from another agent should not be suppressed")
	} else {
		out.Release()
	}
}
