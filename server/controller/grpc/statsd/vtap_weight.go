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
	"encoding/json"
	"sync"
	"time"

	mysql "github.com/deepflowio/deepflow/server/controller/db/metadb"
	"github.com/deepflowio/deepflow/server/controller/statsd"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/deepflowio/deepflow/server/libs/stats/pb"
)

var (
	vtapCounter     *VTapCounter
	vtapCounterOnce sync.Once
)

func GetVTapCounter() *VTapCounter {
	vtapCounterOnce.Do(func() {
		vtapCounter = &VTapCounter{
			ORGIDToVTapNameCounter: make(map[int]VTapNameCounter),
		}
	})
	return vtapCounter
}

type VTapCounter struct {
	mu sync.RWMutex

	ORGIDToVTapNameCounter map[int]VTapNameCounter
}

type VTapNameCounter map[string]*VTapWeightCounter

func (c *VTapCounter) GetVtapNameCounter(orgID int) VTapNameCounter {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ORGIDToVTapNameCounter[orgID] == nil {
		c.ORGIDToVTapNameCounter[orgID] = make(VTapNameCounter)
		log.Infof("init vtap name counter", logger.NewORGPrefix(orgID))
	}
	return c.ORGIDToVTapNameCounter[orgID]
}

func (c *VTapCounter) SetNull(orgID int, vtapName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	vtapNameCounter, ok := c.ORGIDToVTapNameCounter[orgID]
	if !ok {
		return
	}
	counter, ok := vtapNameCounter[vtapName]
	counter.IsAnalyzerChanged = 0
	counter.Weight = 0
}

func (c *VTapCounter) SetCounter(db *mysql.DB, teamID int, vtapName string, weight float64, isChanged uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	vtapNameCounter, ok := c.ORGIDToVTapNameCounter[db.ORGID]
	if !ok {
		log.Warningf("failed to find agent counter to set counter", db.LogPrefixORGID)
		c.ORGIDToVTapNameCounter[db.ORGID] = make(VTapNameCounter)
	}

	if counter, ok := vtapNameCounter[vtapName]; ok {
		if counter.Weight != weight || counter.IsAnalyzerChanged != isChanged {
			log.Infof("agent(%v) update weight: %v -> %v, is_analyzer_changed: %v -> %v",
				vtapName, counter.Weight, weight, counter.IsAnalyzerChanged, isChanged, db.LogPrefixORGID)
		}
		c.ORGIDToVTapNameCounter[db.ORGID][vtapName].Weight = weight
		c.ORGIDToVTapNameCounter[db.ORGID][vtapName].IsAnalyzerChanged = isChanged
		c.ORGIDToVTapNameCounter[db.ORGID][vtapName].ORGID = uint16(db.ORGID)
		c.ORGIDToVTapNameCounter[db.ORGID][vtapName].TeamID = uint16(teamID)
		c.ORGIDToVTapNameCounter[db.ORGID][vtapName].SendStats(vtapName)
		return
	}

	newCounter := &VTapWeightCounter{
		Name: vtapName,

		ORGID:             uint16(db.ORGID),
		TeamID:            uint16(teamID),
		Weight:            weight,
		IsAnalyzerChanged: isChanged,
	}
	b, _ := json.Marshal(newCounter)
	log.Infof("new agent traffic counter: %s", string(b))
	c.ORGIDToVTapNameCounter[db.ORGID][vtapName] = newCounter
	newCounter.SendStats(vtapName)
}

type VTapWeightCounter struct {
	ORGID             uint16
	TeamID            uint16
	Name              string
	Weight            float64
	IsAnalyzerChanged uint64
}

func NewVTapWeightCounter() *VTapWeightCounter {
	return &VTapWeightCounter{}
}

func (v *VTapWeightCounter) SendStats(vtapName string) {
	data := &pb.Stats{
		OrgId:              uint32(v.ORGID),
		TeamId:             uint32(v.TeamID),
		Timestamp:          uint64(time.Now().Unix()),
		Name:               "deepflow_server_agent_analyzer_alloc",
		TagNames:           []string{"host"},
		TagValues:          []string{vtapName},
		MetricsFloatNames:  []string{"is_analyzer_changed", "weight"},
		MetricsFloatValues: []float64{float64(v.IsAnalyzerChanged), v.Weight},
	}
	log.Debugf("send agent(name: %s) traffic counter: %s", vtapName, data.String(), logger.NewORGPrefix(int(v.ORGID)))
	if err := statsd.MetaStatsd.Send(data); err != nil {
		log.Error(err)
	}
}
