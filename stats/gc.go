package stats

import (
	"runtime"
	"time"
)

type GcCountable struct {
	lastPauseDuration uint64
}

func (t *GcCountable) GetCounter() interface{} {
	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)
	gcDuration := memStats.PauseTotalNs - t.lastPauseDuration
	t.lastPauseDuration = memStats.PauseTotalNs
	return []StatItem{{"duration", COUNT_TYPE, gcDuration}}
}

func RegisterGcCountable() {
	registerCountable("gc", &GcCountable{}, OptionInterval(time.Second))
}
