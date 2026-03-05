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
	"strconv"
	"sync"

	"github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

type AgentState struct {
	TenantORGID  string `statsd:"tenant_org_id"`
	TenantTeamID string `statsd:"tenant_team_id"`
	Host         string `statsd:"host"`
	State        uint64 `statsd:"state"`
}

type AgentStateCounter struct {
	mu       sync.Mutex
	Counters []*AgentState
}

func NewAgentStateCounter() *AgentStateCounter {
	return &AgentStateCounter{
		Counters: make([]*AgentState, 0),
	}
}

func (a *AgentStateCounter) GetCounter() interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()

	counters := make([]*AgentState, 0)
	counters, a.Counters = a.Counters, counters
	return counters
}

func (a *AgentStateCounter) AddAgentStateCounters(orgID int, vtaps ...*model.VTap) {
	newAgentCounters := make([]*AgentState, 0, len(vtaps))
	for _, vtap := range vtaps {
		newAgentCounters = append(newAgentCounters, &AgentState{
			TenantORGID:  strconv.Itoa(orgID),
			TenantTeamID: strconv.Itoa(vtap.TeamID),
			Host:         vtap.Name,
			State:        uint64(vtap.State),
		})
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.Counters = append(a.Counters, newAgentCounters...)
}

func (a *AgentStateCounter) Closed() bool {
	return false
}
