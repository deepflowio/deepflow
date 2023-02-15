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
	"github.com/shirou/gopsutil/load"

	"github.com/deepflowio/deepflow/server/libs/stats"
	"github.com/deepflowio/deepflow/server/libs/utils"
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
