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
	cpuPercent float64 `statsd:"cpu-percent"`
	memory     uint64  `statsd:"memory"` // physical + swap in bytes
}

type Monitor struct {
	proc *process.Process
}

func (m *Monitor) GetCounter() interface{} {
	counter := Counter{}
	percent, err := m.proc.CPUPercent()
	if err != nil {
		return counter
	}
	counter.cpuPercent = percent
	mem, err := m.proc.MemoryInfo()
	if err != nil {
		return counter
	}
	counter.memory = mem.RSS + mem.Swap
	return counter
}

func init() {
	proc, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		log.Error(err)
		return
	}
	m := &Monitor{proc}
	stats.RegisterCountable("monitor", stats.EMPTY_TAG, m)
	runtime.SetFinalizer(m, func(m *Monitor) { stats.DeregisterCountable(m) })
}
