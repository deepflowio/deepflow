package queue

import (
	"math"
	"testing"
)

func TestManager(t *testing.T) {
	m := NewManager(1)

	unmarshaller := func(_ interface{}) (interface{}, error) {
		return nil, nil
	}

	m.RecvCommand(nil, nil, math.MaxUint16, nil)
	m.NewQueue("1", 1024)
	if _, ok := m.queues["1"]; !ok {
		t.Error("NewQueue error")
	}
	m.NewQueues("2", 1024, 1, 1)
	if _, ok := m.queues["2"]; !ok {
		t.Error("NewQueues error")
	}
	m.NewQueueUnmarshal("3", 1024, unmarshaller)
	if _, ok := m.queues["3"]; !ok {
		t.Error("NewQueueUnmarshal error")
	}
	m.NewQueuesUnmarshal("4", 1024, 1, 1, unmarshaller)
	if _, ok := m.queues["4"]; !ok {
		t.Error("NewQueuesUnmarshal error")
	}
	cmd := RegisterCommand(1, nil)
	if cmd == nil {
		t.Error("RegisterCommand error")
	}
}
