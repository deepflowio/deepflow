package stats

import (
	"runtime"
	"time"
)

type GcMonitor struct {
	lastPauseDuration uint64
}

func (t *GcMonitor) GetCounter() interface{} {
	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)
	gcDuration := memStats.PauseTotalNs - t.lastPauseDuration
	t.lastPauseDuration = memStats.PauseTotalNs
	return []StatItem{{"duration", COUNT_TYPE, gcDuration}}
}

func RegisterGcMonitor() {
	registerCountable("gc", &GcMonitor{}, OptionInterval(time.Second))
}
