/**
 * Copyright (c) 2023 Yunshan Networks
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

package cache

import (
	"strings"
	"sync"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/side/prometheus/common"
)

type TargetKey struct {
	Instance string `json:"instance"`
	Job      string `json:"job"`
}

func NewTargetKey(instance, job string) TargetKey {
	return TargetKey{
		Instance: instance,
		Job:      job,
	}
}

type target struct {
	keyToTargetID              sync.Map
	labelNames                 []string
	targetIDToLabelNameToValue map[int]map[string]string // only for fully assembled
}

func (t *target) Get() map[int]map[string]string {
	return t.targetIDToLabelNameToValue
}

func (t *target) GetLabelNames() []string {
	return t.labelNames
}

func (t *target) clear() {
	t.targetIDToLabelNameToValue = make(map[int]map[string]string)
}

func (t *target) GetTargetID(key TargetKey) (int, bool) {
	if id, ok := t.keyToTargetID.Load(key); ok {
		return id.(int), true
	}
	return 0, false
}

func (t *target) getLabelNames() []string {
	return t.labelNames
}

func (t *target) refresh(args ...interface{}) error {
	targets, err := t.load()
	if err != nil {
		return err
	}
	fully := args[0].(bool)
	if fully {
		for _, tg := range targets {
			t.keyToTargetID.Store(TargetKey{Instance: tg.Instance, Job: tg.Job}, tg.ID)
			t.targetIDToLabelNameToValue[tg.ID] = t.formatLabels(tg)
		}
	} else {
		for _, tg := range targets {
			t.keyToTargetID.Store(TargetKey{Instance: tg.Instance, Job: tg.Job}, tg.ID)
		}
	}
	return nil
}

func (t *target) formatLabels(tg *mysql.PrometheusTarget) (labelNameToValue map[string]string) {
	labelNameToValue = make(map[string]string)
	labelNameToValue[TargetLabelInstance] = tg.Instance
	labelNameToValue[TargetLabelJob] = tg.Job
	for _, l := range strings.Split(tg.OtherLabels, ",") {
		if l == "" {
			continue
		}
		parts := strings.Split(l, labelJoiner)
		if len(parts) != 2 {
			continue
		}
		labelNameToValue[parts[0]] = parts[1]
	}
	return
}

func (t *target) load() ([]*mysql.PrometheusTarget, error) {
	var targets []*mysql.PrometheusTarget
	err := mysql.Db.Find(&targets).Error
	return targets, err
}
