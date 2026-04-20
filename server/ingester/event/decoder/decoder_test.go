package decoder

import (
	"testing"

	"github.com/deepflowio/deepflow/server/ingester/event/common"
	"github.com/deepflowio/deepflow/server/libs/flow-metrics/pb"
)

func TestRouteProcEventType(t *testing.T) {
	tests := []struct {
		name  string
		event *pb.ProcEvent
		want  common.EventType
	}{
		{
			name: "io event keeps file_event",
			event: &pb.ProcEvent{
				EventType:   pb.EventType_IoEvent,
				IoEventData: &pb.IoEventData{},
			},
			want: common.FILE_EVENT,
		},
		{
			name: "file op goes to file_mgmt_event",
			event: &pb.ProcEvent{
				EventType: pb.EventType_FileOpEvent,
				FileOpEventData: &pb.FileOpEventData{
					OpType: pb.FileOpType_FileOpCreate,
				},
			},
			want: common.FILE_MGMT_EVENT,
		},
		{
			name: "perm op goes to proc_perm_event",
			event: &pb.ProcEvent{
				EventType: pb.EventType_PermOpEvent,
				PermOpEventData: &pb.PermOpEventData{
					OpType: pb.PermOpType_PermOpSetuid,
				},
			},
			want: common.PROC_PERM_EVENT,
		},
		{
			name: "proc lifecycle goes to proc_ops_event",
			event: &pb.ProcEvent{
				EventType: pb.EventType_ProcLifecycleEvent,
				ProcLifecycleEventData: &pb.ProcLifecycleEventData{
					LifecycleType: pb.ProcLifecycleType_ProcLifecycleFork,
				},
			},
			want: common.PROC_OPS_EVENT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := routeProcEventType(tt.event); got != tt.want {
				t.Fatalf("routeProcEventType() = %v, want %v", got, tt.want)
			}
		})
	}
}

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

func TestResolveGProcessIDExitEventClearsCacheWhenParentPidMissing(t *testing.T) {
	orgId := uint16(1)
	vtapId := uint16(2)
	pid := uint32(9100)
	cache := NewAiAgentRootPidCache()
	cache.Set(orgId, vtapId, pid, pid)

	event := &pb.ProcEvent{
		Pid:       pid,
		EventType: pb.EventType_ProcLifecycleEvent,
		ProcLifecycleEventData: &pb.ProcLifecycleEventData{
			LifecycleType: pb.ProcLifecycleType_ProcLifecycleExit,
			Pid:           pid,
			ParentPid:     0,
		},
	}

	got := resolveGProcessID(func(uint32) uint32 { return 0 }, cache, orgId, vtapId, event)
	if got != 0 {
		t.Fatalf("expected gprocess_id 0 for exit event, got %d", got)
	}
	if _, ok := cache.Get(orgId, vtapId, pid); ok {
		t.Fatalf("expected pid %d to be removed from cache on exit", pid)
	}
}

func TestResolveGProcessIDExitEventClearsCacheWhenParentLookupMisses(t *testing.T) {
	orgId := uint16(1)
	vtapId := uint16(2)
	pid := uint32(9200)
	parentPid := uint32(9300)
	cache := NewAiAgentRootPidCache()
	cache.Set(orgId, vtapId, pid, pid)

	event := &pb.ProcEvent{
		Pid:       pid,
		EventType: pb.EventType_ProcLifecycleEvent,
		ProcLifecycleEventData: &pb.ProcLifecycleEventData{
			LifecycleType: pb.ProcLifecycleType_ProcLifecycleExit,
			Pid:           pid,
			ParentPid:     parentPid,
		},
	}

	got := resolveGProcessID(func(uint32) uint32 { return 0 }, cache, orgId, vtapId, event)
	if got != 0 {
		t.Fatalf("expected gprocess_id 0 for exit event, got %d", got)
	}
	if _, ok := cache.Get(orgId, vtapId, pid); ok {
		t.Fatalf("expected pid %d to be removed from cache when parent lookup misses", pid)
	}
}

func TestExtractProcOpsCommandData(t *testing.T) {
	event := &pb.ProcEvent{
		EventType: pb.EventType_ProcLifecycleEvent,
		ProcLifecycleEventData: &pb.ProcLifecycleEventData{
			LifecycleType: pb.ProcLifecycleType_ProcLifecycleExec,
			Cmdline:       []byte("python3.11 batch_processor.py --interval=300"),
			ExecPath:      []byte("/usr/bin/python3.11"),
		},
	}

	cmdline, execPath := extractProcOpsCommandData(event)
	if cmdline != "python3.11 batch_processor.py --interval=300" {
		t.Fatalf("cmdline = %q", cmdline)
	}
	if execPath != "/usr/bin/python3.11" {
		t.Fatalf("exec_path = %q", execPath)
	}
}

func TestExtractFileMgmtTargets(t *testing.T) {
	uid, gid, mode := extractFileMgmtTargets(&pb.FileOpEventData{
		OpType: pb.FileOpType_FileOpChown,
		Uid:    1001,
		Gid:    1002,
	})
	if uid != 1001 || gid != 1002 || mode != 0 {
		t.Fatalf("chown targets = (%d,%d,%d)", uid, gid, mode)
	}

	uid, gid, mode = extractFileMgmtTargets(&pb.FileOpEventData{
		OpType: pb.FileOpType_FileOpChmod,
		Mode:   0600,
	})
	if uid != 0 || gid != 0 || mode != 0600 {
		t.Fatalf("chmod targets = (%d,%d,%d)", uid, gid, mode)
	}
}

func TestShouldAggregateFileAggEvent(t *testing.T) {
	if shouldAggregateFileAggEvent(0) {
		t.Fatalf("expected root pid 0 to skip file_agg_event aggregation")
	}
	if !shouldAggregateFileAggEvent(42) {
		t.Fatalf("expected non-zero root pid to allow file_agg_event aggregation")
	}
}
