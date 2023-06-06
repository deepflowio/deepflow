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

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

var (
	labelJoiner   = ", "
	labelKVJoiner = ":"
)

type TargetKey struct {
	Instance string
	Job      string
}

func NewTargetKey(instance, job string) TargetKey {
	return TargetKey{
		Instance: instance,
		Job:      job,
	}
}

type TargetLabelKey struct {
	TargetID  int    `json:"target_id"`
	LabelName string `json:"label_name"`
}

func NewTargetLabelKey(targetID int, labelName string) TargetLabelKey {
	return TargetLabelKey{
		TargetID:  targetID,
		LabelName: labelName,
	}
}

type targetLabelNameToValue map[string]string

type target struct {
	keyToTargetID   sync.Map
	targetLabelKeys mapset.Set[TargetLabelKey]
}

func newTarget() *target {
	return &target{
		targetLabelKeys: mapset.NewSet[TargetLabelKey](),
	}
}

func (t *target) Get() *sync.Map {
	return &t.keyToTargetID
}

func (t *target) IfTargetLabelKeyExists(key TargetLabelKey) bool {
	return t.targetLabelKeys.Contains(key)
}

func (t *target) GetIDByKey(key TargetKey) (int, bool) {
	if id, ok := t.keyToTargetID.Load(key); ok {
		return id.(int), true
	}
	return 0, false
}

func (t *target) refresh(args ...interface{}) error {
	targets, err := t.load()
	if err != nil {
		return err
	}
	fully := args[0].(bool)
	for _, item := range targets {
		key := NewTargetKey(item.Instance, item.Job)
		t.keyToTargetID.Store(key, item.ID)
		if !fully {
			for _, ln := range t.getTargetLabelNames(item) {
				t.targetLabelKeys.Add(NewTargetLabelKey(item.ID, ln))
			}
		}
	}
	return nil
}

func (t *target) getTargetLabelNames(tg *mysql.PrometheusTarget) []string {
	var lns []string
	for _, l := range strings.Split(tg.OtherLabels, labelJoiner) {
		if l == "" {
			continue
		}
		parts := strings.Split(l, labelKVJoiner)
		if len(parts) != 2 {
			log.Warningf("invalid label: %s", l)
			continue
		}
		lns = append(lns, parts[0])
	}
	return lns
}

func (t *target) load() ([]*mysql.PrometheusTarget, error) {
	var targets []*mysql.PrometheusTarget
	err := mysql.Db.Find(&targets).Error
	return targets, err
}
