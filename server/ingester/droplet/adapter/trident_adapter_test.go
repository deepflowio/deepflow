package adapter

import (
	"math"
	"reflect"
	"testing"

	"github.com/metaflowys/metaflow/server/ingester/droplet/queue"
)

func TestTridentAdapter(t *testing.T) {
	manager := queue.NewManager(1)
	queues := manager.NewQueues("1-meta-packet-block-to-labeler", 1<<10, 1, 1)
	adapter := NewTridentAdapter(nil, queues.Writers(), 1<<20)

	count := adapter.GetStatsCounter()
	if !reflect.DeepEqual(count, &PacketCounter{}) {
		t.Errorf("GetStatsCounter expect %v actual: %v", &PacketCounter{}, count)
	}
	count = adapter.GetCounter()
	if !reflect.DeepEqual(count, &PacketCounter{}) {
		t.Errorf("GetCounter expect %v actual: %v", &PacketCounter{}, count)
	}
	instances := adapter.GetInstances()
	if len(instances) > 0 {
		t.Errorf("GetInstances expect %v actual: %v", 0, len(instances))
	}
	// command test
	adapter.RecvCommand(nil, nil, math.MaxUint16, nil)
	cobra := RegisterCommand(1)
	if cobra == nil {
		t.Error("RegisterCommand return nil")
	}
}
