package stats

import (
	"runtime"
	"time"

	"gitlab.yunshan.net/yunshan/droplet-libs/utils"
)

type GcMonitor struct {
	utils.Closable

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
