/*
 * Copyright (c) 2024 Yunshan Networks
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

package statsd

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type AgentAttr struct {
	TenantORGID  string `statsd:"tenant_org_id"`
	TenantTeamID string `statsd:"tenant_team_id"`
	Host         string `statsd:"host"`
	State        uint64 `statsd:"state"`
	Exceptions   uint64 `statsd:"exceptions"`
}

type AgentAttrCounter struct {
	mu       sync.Mutex
	Counters map[string]*AgentAttr
}

func NewAgentAttrCounter() *AgentAttrCounter {
	return &AgentAttrCounter{
		Counters: make(map[string]*AgentAttr),
	}
}

func (a *AgentAttrCounter) GetCounter() interface{} {
	counters := make(map[string]*AgentAttr)
	a.mu.Lock()
	counters, a.Counters = a.Counters, counters
	a.mu.Unlock()

	result := make([]*AgentAttr, 0, len(counters))
	for _, counter := range counters {
		result = append(result, counter)
	}
	return result
}

func (a *AgentAttrCounter) AddAgentAttrCounters(orgID int, vtaps ...*model.VTap) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, vtap := range vtaps {
		a.Counters[fmt.Sprintf("%d-%d", orgID, vtap.ID)] = &AgentAttr{
			TenantORGID:  strconv.Itoa(orgID),
			TenantTeamID: strconv.Itoa(vtap.TeamID),
			Host:         vtap.Name,
			State:        uint64(vtap.State),
			Exceptions:   uint64(vtap.Exceptions),
		}
	}
}

func (a *AgentAttrCounter) Closed() bool {
	return false
}
