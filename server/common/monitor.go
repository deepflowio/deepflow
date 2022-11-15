package common

import (
	"os"
	"runtime"

	"github.com/deepflowys/deepflow/server/libs/stats"
	"github.com/deepflowys/deepflow/server/libs/utils"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

func (m *Monitor) GetCpuPercent() float64 {
	if percent, err := m.process.Percent(0); err == nil {
		return percent
	}
	return 0
}

func (m *Monitor) GetMemRSS() uint64 {
	if memInfo, err := m.process.MemoryInfo(); err == nil {
		return memInfo.RSS
	}
	return 0
}

func GetMemInuse() uint64 {
	var memStat runtime.MemStats
	runtime.ReadMemStats(&memStat)
	return memStat.HeapInuse + memStat.StackInuse
}

func GetNetIO() (uint64, uint64) {
	if info, err := net.IOCounters(false); err == nil {
		return info[0].BytesSent, info[0].BytesRecv
	}
	return 0, 0
}

func (m *Monitor) GetDiskIO() (uint64, uint64) {
	if info, err := m.process.IOCounters(); err == nil {
		return info.ReadBytes, info.WriteBytes
	}
	return 0, 0
}

type Monitor struct {
	process *process.Process

	utils.Closable
}

type Counter struct {
	CpuPercent float64 `statsd:"cpu-percent"`
	MemRSS     uint64  `statsd:"mem-rss"`
	MemInuse   uint64  `statsd:"mem-inuse"`
	BytesSend  uint64  `statsd:"bytes-send"`
	BytesRecv  uint64  `statsd:"bytes-recv"`
	BytesRead  uint64  `statsd:"bytes-read"`
	BytesWrite uint64  `statsd:"bytes-write"`
}

func NewMonitor() (*Monitor, error) {
	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		return nil, err
	}
	m := &Monitor{
		process: p,
	}

	stats.RegisterCountable("monitor", m)
	return m, nil
}

func (m *Monitor) GetCounter() interface{} {
	bytesSend, bytesRecv := GetNetIO()
	bytesRead, bytesWrite := m.GetDiskIO()
	return &Counter{
		CpuPercent: m.GetCpuPercent(),
		MemRSS:     m.GetMemRSS(),
		MemInuse:   GetMemInuse(),
		BytesSend:  bytesSend,
		BytesRecv:  bytesRecv,
		BytesRead:  bytesRead,
		BytesWrite: bytesWrite,
	}
}

func (m *Monitor) Stop() {
	m.Close()
}
