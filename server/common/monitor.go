package common

import (
	"os"
	"runtime"

	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

const ENV_K8S_NODE_IP = "K8S_NODE_IP_FOR_DEEPFLOW"

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

func (m *Monitor) GetLoad1() float64 {
	if loadInfo, err := load.Avg(); err == nil {
		return loadInfo.Load1
	}
	return 0
}

func (m *Monitor) GetCpuNum() uint64 {
	cpuNum, err := cpu.Counts(true)
	if err != nil {
		cpuNum = runtime.NumCPU()
	}
	return uint64(cpuNum)
}

type Monitor struct {
	process             *process.Process
	lastRecv, lastSend  uint64
	lastRead, lastWrite uint64

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
	Load1      float64 `statsd:"load1"`
	CPUNum     uint64  `statsd:"cpu-num"`
}

func NewMonitor() (*Monitor, error) {
	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		return nil, err
	}
	m := &Monitor{
		process: p,
	}
	myNodeIP, _ := os.LookupEnv(ENV_K8S_NODE_IP)
	stats.RegisterCountable("monitor", m, stats.OptionStatTags{"host_ip": myNodeIP})
	return m, nil
}

func (m *Monitor) GetCounter() interface{} {
	bytesSend, bytesRecv := GetNetIO()
	bytesRead, bytesWrite := m.GetDiskIO()
	c := &Counter{
		CpuPercent: m.GetCpuPercent(),
		MemRSS:     m.GetMemRSS(),
		MemInuse:   GetMemInuse(),
		BytesSend:  bytesSend - m.lastSend,
		BytesRecv:  bytesRecv - m.lastRecv,
		BytesRead:  bytesRead - m.lastRead,
		BytesWrite: bytesWrite - m.lastWrite,
		Load1:      m.GetLoad1(),
		CPUNum:     m.GetCpuNum(),
	}
	m.lastSend, m.lastRecv = bytesSend, bytesRecv
	m.lastRead, m.lastWrite = bytesRead, bytesWrite
	return c
}

func (m *Monitor) Stop() {
	m.Close()
}
