package decoder

import (
	"testing"

	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
)

func TestResolveGProcessIDProcLifecycleFallback(t *testing.T) {
	parentPid := uint32(2000)
	childPid := uint32(3000)
	parentGpid := uint32(42)

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
		},
	}

	got := resolveGProcessID(query, event)
	if got != parentGpid {
		t.Fatalf("expected gprocess_id fallback to parent %d, got %d", parentGpid, got)
	}
}
