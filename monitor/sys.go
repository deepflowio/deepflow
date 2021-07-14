package monitor

import (
	"os"

	"github.com/op/go-logging"
	"github.com/shirou/gopsutil/process"

	"gitlab.yunshan.net/yunshan/droplet-libs/stats"
)

var log = logging.MustGetLogger("monitor")

type SysCounter struct {
	CpuPercent float64 `statsd:"cpu_percent,gauge"`
	Memory     uint64  `statsd:"memory,gauge"` // physical in bytes
}

type Monitor process.Process

func (m *Monitor) GetCounter() interface{} {
	percent, err := (*process.Process)(m).Percent(0)
	if err != nil {
		return SysCounter{}
	}
	mem, err := (*process.Process)(m).MemoryInfo()
	if err != nil {
		return SysCounter{}
	}
	return SysCounter{percent, mem.RSS}
}

func (m *Monitor) Closed() bool {
	return false
}

func init() {
	proc, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		log.Errorf("%v", err)
		return
	}
	m := (*Monitor)(proc)
	stats.RegisterCountable("monitor", m)
}
