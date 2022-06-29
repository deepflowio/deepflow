package monitor

import (
	"github.com/shirou/gopsutil/load"

	"github.com/metaflowys/metaflow/server/libs/stats"
	"github.com/metaflowys/metaflow/server/libs/utils"
)

type LoadMonitor struct {
	utils.Closable
}

func (m *LoadMonitor) GetCounter() interface{} {
	if loadInfo, err := load.Avg(); err != nil {
		return []stats.StatItem{stats.StatItem{Name: "load1", Value: 0}}
	} else {
		return []stats.StatItem{stats.StatItem{Name: "load1", Value: loadInfo.Load1}}
	}
}

func init() {
	m := &LoadMonitor{}
	stats.RegisterCountable("load", m)
}
