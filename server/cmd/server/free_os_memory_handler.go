package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/ingesterctl"
	debugcmd "github.com/deepflowio/deepflow/server/libs/debug"
)

const (
	DEFAULT_FREE_INTERVAL_SECOND = 3600
)

func getMemUsage(tag string) string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf("%s Memory Usage: Alloc=%d MB, Sys=%d MB, NumGC=%d",
		tag, bToMb(m.Alloc), bToMb(m.Sys), m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

type FreeOSMemoryHandler struct {
	enabled  bool
	interval int
	ticker   *time.Ticker
	running  bool
}

func NewFreeOSMemoryHandler(cfg *FreeOSMemoryManager) *FreeOSMemoryHandler {
	f := &FreeOSMemoryHandler{
		enabled:  cfg.Enabled,
		interval: cfg.Interval,
	}
	if f.interval == 0 {
		f.interval = DEFAULT_FREE_INTERVAL_SECOND
	}

	debugcmd.ServerRegisterSimple(ingesterctl.CMD_FREE_OS_MEMORY, f)
	return f
}

func (f *FreeOSMemoryHandler) Run() {
	f.running = true
	f.ticker = time.NewTicker(time.Duration(f.interval) * time.Second)
	for f.running {
		select {
		case <-f.ticker.C:
			log.Info(getMemUsage("Before FreeOSMemory(),"))
			debug.FreeOSMemory()
			log.Info(getMemUsage("After FreeOSMemory(),"))
		}
	}
	f.ticker.Stop()
	f.ticker = nil
}

func (f *FreeOSMemoryHandler) Start(force bool) string {
	if !f.enabled && !force {
		return logInfo("FreeOSMemory() interval execution disabled")
	}
	if f.running {
		return logInfo("FreeOSMemory() interval execution already running")
	}
	go f.Run()
	return logInfo(fmt.Sprintf("starting FreeOSMemory() interval execution with interval %ds", f.interval))
}

func (f *FreeOSMemoryHandler) Stop() string {
	if !f.running {
		return logInfo("FreeOSMemory() interval execution already stopped")
	}

	f.running = false
	return logInfo("FreeOSMemory() interval execution is stopping")
}

func (f *FreeOSMemoryHandler) CallFreeOSMemoryOnce() string {
	before := getMemUsage("\nBefore FreeOSMemory(), ")
	debug.FreeOSMemory()
	after := getMemUsage("\nAfter FreeOSMemory(), ")
	return before + after
}

func (f *FreeOSMemoryHandler) SetInterval(interval int) string {
	if interval <= 0 {
		return logInfo(fmt.Sprintf("invalid interval value %d, should > 0", interval))
	}
	if f.ticker != nil {
		f.interval = interval
		f.ticker.Reset(time.Duration(f.interval) * time.Second)
		return logInfo(fmt.Sprintf("set interval to %d second", f.interval))
	} else {
		return logInfo("FreeOSMemory() interval execution is not running and interval cannot be set")
	}
}

const (
	CMD_FREE_OS_MEMORY_ON uint16 = iota
	CMD_FREE_OS_MEMORY_OFF
	CMD_FREE_OS_MEMORY_ONCE
	CMD_FREE_OS_MEMORY_STATUS
	CMD_FREE_OS_MEMORY_SET_INTERVAL
)

func (f *FreeOSMemoryHandler) HandleSimpleCommand(op uint16, arg string) string {
	switch op {
	case CMD_FREE_OS_MEMORY_ON:
		return f.Start(true)
	case CMD_FREE_OS_MEMORY_OFF:
		return f.Stop()
	case CMD_FREE_OS_MEMORY_ONCE:
		return f.CallFreeOSMemoryOnce()
	case CMD_FREE_OS_MEMORY_STATUS:
		if f.running {
			return fmt.Sprintf("running with interval %d", f.interval)
		}
		return "stopped"
	case CMD_FREE_OS_MEMORY_SET_INTERVAL:
		interval := 0
		if arg != "" {
			interval, _ = strconv.Atoi(arg)
		}
		return f.SetInterval(interval)
	}

	return logInfo("invalid op")
}
