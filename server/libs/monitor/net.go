/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package monitor

import (
	. "net"

	"github.com/shirou/gopsutil/net"

	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
)

var (
	monitors = make(map[string]*NetworkMonitor)
)

type NetCounter struct {
	Rx      uint64 `statsd:"rx,counter"`
	Tx      uint64 `statsd:"tx,counter"`
	RxBytes uint64 `statsd:"rx_bytes,counter"`
	TxBytes uint64 `statsd:"tx_bytes,counter"`
	ErrIn   uint64 `statsd:"err_in,counter"`
	ErrOut  uint64 `statsd:"err_out,counter"`
	DropIn  uint64 `statsd:"drop_in,counter"`
	DropOut uint64 `statsd:"drop_out,counter"`
	FifoIn  uint64 `statsd:"fifo_in,counter"`
	FifoOut uint64 `statsd:"fifo_out,counter"`
}

type NetworkMonitor struct {
	utils.Closable

	old, new net.IOCountersStat
}

func (m *NetworkMonitor) GetCounter() interface{} {
	c := NetCounter{
		m.new.PacketsRecv - m.old.PacketsRecv,
		m.new.PacketsSent - m.old.PacketsSent,
		m.new.BytesRecv - m.old.BytesRecv,
		m.new.BytesSent - m.old.BytesSent,
		m.new.Errin - m.old.Errin,
		m.new.Errout - m.old.Errout,
		m.new.Dropin - m.old.Dropin,
		m.new.Dropout - m.old.Dropout,
		m.new.Fifoin - m.old.Fifoin,
		m.new.Fifoout - m.old.Fifoout,
	}
	m.old = m.new
	return c
}

var hookCounter = 10

func preHook() {
	hookCounter++
	if hookCounter < 10 { // hook 1秒调用一次，因此每第10次更新一次数据
		return
	} else {
		hookCounter = 0
	}

	var toAdd, toDel []string
	interfaceMap := map[string]bool{}
	counters, _ := net.IOCounters(true)

	for _, counter := range counters {
		interfaceMap[counter.Name] = true
	}
	for ifName, m := range monitors {
		if _, found := interfaceMap[ifName]; found {
			continue
		}
		m.Close()
		delete(monitors, ifName)
		toDel = append(toDel, ifName)
	}
	if len(toDel) > 0 {
		log.Debug("Removing:", toDel)
	}

	for _, counter := range counters {
		m := monitors[counter.Name]
		if m != nil {
			m.new = counter
			continue
		}
		iface, err := InterfaceByName(counter.Name)
		if err != nil {
			log.Warning(err)
			continue
		}
		var mac string
		if counter.Name == "lo" {
			mac = "00:00:00:00:00:00"
		} else {
			mac = iface.HardwareAddr.String()
		}
		m = &NetworkMonitor{false, counter, counter}
		tags := stats.OptionStatTags{"name": counter.Name, "mac": mac}
		stats.RegisterCountable("net", m, tags)
		monitors[counter.Name] = m
		toAdd = append(toAdd, counter.Name)
	}
	if len(toAdd) > 0 {
		log.Debug("Monitoring:", toAdd)
	}
}

func init() {
	stats.RegisterPreHook(preHook)
}
