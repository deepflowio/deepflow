package monitor

import (
	"os"
	"runtime"

	"github.com/op/go-logging"
	"github.com/shirou/gopsutil/process"

	"gitlab.x.lan/yunshan/droplet-libs/stats"
)

var log = logging.MustGetLogger("monitor")

type Counter struct {
	CpuPercent float64 `statsd:"cpu_percent"`
	Memory     uint64  `statsd:"memory"` // physical + swap in bytes
}

type Monitor process.Process

func (m *Monitor) GetCounter() interface{} {
	counter := Counter{}
	percent, err := (*process.Process)(m).CPUPercent()
	if err != nil {
		return counter
	}
	counter.CpuPercent = percent
	mem, err := (*process.Process)(m).MemoryInfo()
	if err != nil {
		return counter
	}
	counter.Memory = mem.RSS + mem.Swap
	return counter
}

func init() {
	proc, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		log.Errorf("%v", err)
		return
	}
	m := (*Monitor)(proc)
	stats.RegisterCountable("monitor", m)
	runtime.SetFinalizer(m, func(m *Monitor) { stats.DeregisterCountable(m) })
}
