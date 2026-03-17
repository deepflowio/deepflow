package decoder

import (
	"testing"

	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
)

func TestResolveGProcessIDProcLifecycleFallback(t *testing.T) {
	parentPid := uint32(2000)
	childPid := uint32(3000)
	parentGpid := uint32(42)
	orgId := uint16(1)
	vtapId := uint16(2)
	cache := NewAiAgentRootPidCache()

	query := func(pid uint32) uint32 {
		if pid == parentPid {
			return parentGpid
		}
		return 0
	}

	event := &pb.ProcEvent{
		Pid:       childPid,
		EventType: pb.EventType_ProcLifecycleEvent,
		ProcLifecycleEventData: &pb.ProcLifecycleEventData{
			ParentPid: parentPid,
			Pid:       childPid,
		},
	}

	got := resolveGProcessID(query, cache, orgId, vtapId, event)
	if got != parentGpid {
		t.Fatalf("expected gprocess_id fallback to parent %d, got %d", parentGpid, got)
	}
}

func TestResolveGProcessIDChildInheritsRoot(t *testing.T) {
	orgId := uint16(1)
	vtapId := uint16(2)
	parentPid := uint32(4000)
	childPid := uint32(5000)
	grandPid := uint32(6000)
	parentGpid := uint32(77)
	cache := NewAiAgentRootPidCache()

	query := func(pid uint32) uint32 {
		if pid == parentPid {
			return parentGpid
		}
		return 0
	}

	forkChild := &pb.ProcEvent{
		Pid:       childPid,
		EventType: pb.EventType_ProcLifecycleEvent,
		ProcLifecycleEventData: &pb.ProcLifecycleEventData{
			LifecycleType: pb.ProcLifecycleType_ProcLifecycleFork,
			ParentPid:     parentPid,
			Pid:           childPid,
		},
	}
	if got := resolveGProcessID(query, cache, orgId, vtapId, forkChild); got != parentGpid {
		t.Fatalf("expected child inherit gprocess_id %d, got %d", parentGpid, got)
	}

	forkGrand := &pb.ProcEvent{
		Pid:       grandPid,
		EventType: pb.EventType_ProcLifecycleEvent,
		ProcLifecycleEventData: &pb.ProcLifecycleEventData{
			LifecycleType: pb.ProcLifecycleType_ProcLifecycleFork,
			ParentPid:     childPid,
			Pid:           grandPid,
		},
	}
	if got := resolveGProcessID(query, cache, orgId, vtapId, forkGrand); got != parentGpid {
		t.Fatalf("expected grandchild inherit gprocess_id %d, got %d", parentGpid, got)
	}

	fileOp := &pb.ProcEvent{
		Pid:       grandPid,
		EventType: pb.EventType_FileOpEvent,
		FileOpEventData: &pb.FileOpEventData{
			OpType: pb.FileOpType_FileOpCreate,
		},
	}
	if got := resolveGProcessID(query, cache, orgId, vtapId, fileOp); got != parentGpid {
		t.Fatalf("expected file event inherit gprocess_id %d, got %d", parentGpid, got)
	}
}

func TestResolveGProcessIDExecKeepsSelfWhenUncached(t *testing.T) {
	orgId := uint16(1)
	vtapId := uint16(2)
	pid := uint32(7000)
	parentPid := uint32(8000)
	pidGpid := uint32(88)
	cache := NewAiAgentRootPidCache()

	query := func(id uint32) uint32 {
		if id == pid {
			return pidGpid
		}
		return 0
	}

	execEvent := &pb.ProcEvent{
		Pid:       pid,
		EventType: pb.EventType_ProcLifecycleEvent,
		ProcLifecycleEventData: &pb.ProcLifecycleEventData{
			LifecycleType: pb.ProcLifecycleType_ProcLifecycleExec,
			ParentPid:     parentPid,
			Pid:           pid,
		},
	}
	if got := resolveGProcessID(query, cache, orgId, vtapId, execEvent); got != pidGpid {
		t.Fatalf("expected exec event use self gprocess_id %d, got %d", pidGpid, got)
	}
}

func TestResolveGProcessIDAiAgentRootPidFallback(t *testing.T) {
	orgId := uint16(1)
	vtapId := uint16(2)
	rootPid := uint32(1000)
	childPid := uint32(2000)
	rootGpid := uint32(55)
	cache := NewAiAgentRootPidCache()

	query := func(pid uint32) uint32 {
		if pid == rootPid {
			return rootGpid
		}
		return 0
	}

	// File event from a child process that isn't in the process table yet,
	// but carries the root AI Agent PID from the agent registry.
	fileEvent := &pb.ProcEvent{
		Pid:             childPid,
		EventType:       pb.EventType_FileOpEvent,
		AiAgentRootPid:  rootPid,
		FileOpEventData: &pb.FileOpEventData{OpType: pb.FileOpType_FileOpCreate},
	}
	got := resolveGProcessID(query, cache, orgId, vtapId, fileEvent)
	if got != rootGpid {
		t.Fatalf("expected ai_agent_root_pid fallback to gprocess_id %d, got %d", rootGpid, got)
	}

	// After the first resolution, the cache should be populated so
	// subsequent events for the same child resolve without the fallback.
	query2 := func(pid uint32) uint32 {
		if pid == rootPid {
			return rootGpid
		}
		return 0
	}
	fileEvent2 := &pb.ProcEvent{
		Pid:         childPid,
		EventType:   pb.EventType_IoEvent,
		IoEventData: &pb.IoEventData{},
	}
	got2 := resolveGProcessID(query2, cache, orgId, vtapId, fileEvent2)
	if got2 != rootGpid {
		t.Fatalf("expected cached root_pid resolution to gprocess_id %d, got %d", rootGpid, got2)
	}
}
