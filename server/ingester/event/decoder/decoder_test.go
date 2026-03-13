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
