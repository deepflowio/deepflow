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

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/libs/stats"
)

var (
	vtapCounter     *VTapCounter
	vtapCounterOnce sync.Once
)

func GetVTapCounter() *VTapCounter {
	vtapCounterOnce.Do(func() {
		vtapCounter = &VTapCounter{
			VTapNameCounter: make(map[string]*GetVTapWeightCounter),
		}
	})
	return vtapCounter
}

type VTapCounter struct {
	mu sync.Mutex

	VTapNameCounter map[string]*GetVTapWeightCounter
}

func (c *VTapCounter) SetNull(vtapName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	counter, ok := c.VTapNameCounter[vtapName]
	if !ok {
		return
	}
	counter.IsAnalyzerChanged = 0
	counter.Weight = 0
}

func (c *VTapCounter) SetCounter(db *mysql.DB, teamID int, vtapName string, weight float64, isChanged uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if counter, ok := c.VTapNameCounter[vtapName]; ok {
		if counter.Weight != weight || counter.IsAnalyzerChanged != isChanged {
			log.Infof("ORG(id=%d database=%s) agent(%v) update weight: %v -> %v, is_analyzer_changed: %v -> %v",
				db.ORGID, db.Name, vtapName, counter.Weight, weight, counter.IsAnalyzerChanged, isChanged)
		}
		counter.Weight = weight
		counter.IsAnalyzerChanged = isChanged
		counter.ORGID = uint16(db.ORGID)
		counter.TeamID = uint16(teamID)
		return
	}

	newCounter := &GetVTapWeightCounter{
		Name: vtapName,
		VTapWeightCounter: &VTapWeightCounter{
			ORGID:             uint16(db.ORGID),
			TeamID:            uint16(teamID),
			Weight:            weight,
			IsAnalyzerChanged: isChanged,
		},
	}
	c.VTapNameCounter[vtapName] = newCounter
	b, _ := json.Marshal(newCounter.VTapWeightCounter)
	log.Infof("ORG(id=%d database=%s) agent(%v) register counter: %v", db.ORGID, db.Name, vtapName, string(b))
	err := stats.RegisterCountableWithModulePrefix("controller_", "analyzer_alloc", newCounter, stats.OptionStatTags{"host": vtapName})
	if err != nil {
		log.Errorf("ORG(id=%d database=%s) %s", db.ORGID, db.Name, err.Error())
	}
}

type VTapWeightCounter struct {
	ORGID             uint16  `statsd:"org_id"`
	TeamID            uint16  `statsd:"team_id"`
	Weight            float64 `statsd:"weight"`
	IsAnalyzerChanged uint64  `statsd:"is_analyzer_changed"`
}

func NewVTapWeightCounter() *VTapWeightCounter {
	return &VTapWeightCounter{}
}

type GetVTapWeightCounter struct {
	*VTapWeightCounter
	Name string
}

func (g *GetVTapWeightCounter) GetCounter() interface{} {
	return g.VTapWeightCounter
}

func (g *GetVTapWeightCounter) Closed() bool {
	return false
}
