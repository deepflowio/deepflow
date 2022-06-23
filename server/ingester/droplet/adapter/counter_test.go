package adapter

import (
	"reflect"
	"testing"
)

func TestCounter(t *testing.T) {
	base := &PacketCounter{10, 10, 10, 10, 10}

	statsCounter := &statsCounter{}
	statsCounter.init()

	statsCounter.counter.add(base)
	statsCounter.stats.add(base)

	count := statsCounter.GetStatsCounter()
	if !reflect.DeepEqual(count, base) {
		t.Errorf("GetStatsCounter expect %v actual: %v", base, count)
	}

	count = statsCounter.GetCounter()
	if !reflect.DeepEqual(count, base) {
		t.Errorf("GetCounter expect %v actual: %v", base, count)
	}

	count = statsCounter.GetStatsCounter()
	if !reflect.DeepEqual(count, base) {
		t.Errorf("GetStatsCounter expect %v actual: %v", base, count)
	}

	count = statsCounter.GetCounter()
	if !reflect.DeepEqual(count, &PacketCounter{}) {
		t.Errorf("GetCounter expect %v actual: %v", &PacketCounter{}, count)
	}
}
