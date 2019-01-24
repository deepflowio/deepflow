package stats

import (
	"runtime"
	"time"
)

type GcMonitor struct {
	Closable

	lastPauseDuration uint64
}

func (t *GcMonitor) GetCounter() interface{} {
	memStats := runtime.MemStats{}
	runtime.ReadMemStats(&memStats)
	gcDuration := memStats.PauseTotalNs - t.lastPauseDuration
	t.lastPauseDuration = memStats.PauseTotalNs
	return []StatItem{{"duration", gcDuration}}
}

func RegisterGcMonitor() {
	registerCountable("gc", &GcMonitor{}, OptionInterval(time.Second))
}
