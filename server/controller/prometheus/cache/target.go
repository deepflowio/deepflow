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
	. "github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

var (
	labelKVJoiner = ":"
	labelJoiner   = ", "
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

type targetLabelNameToValue map[string]string

type target struct {
	keyToTargetID              sync.Map
	targetIDToLabelNameToValue sync.Map
}

func (t *target) Get() *sync.Map {
	return &t.keyToTargetID
}

func (t *target) GetLabelNameToValueByID(i int) targetLabelNameToValue {
	if labelNameToValue, ok := t.targetIDToLabelNameToValue.Load(i); ok {
		return labelNameToValue.(targetLabelNameToValue)
	}
	return make(targetLabelNameToValue)
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
			t.targetIDToLabelNameToValue.Store(item.ID, t.formatLabels(item))
		}
	}
	return nil
}

func (t *target) formatLabels(tg *mysql.PrometheusTarget) (labelNameToValue targetLabelNameToValue) {
	labelNameToValue = make(targetLabelNameToValue)
	labelNameToValue[TargetLabelInstance] = tg.Instance
	labelNameToValue[TargetLabelJob] = tg.Job
	for _, l := range strings.Split(tg.OtherLabels, labelJoiner) {
		if l == "" {
			continue
		}
		k, v, ok := strings.Cut(l, labelKVJoiner)
		if !ok {
			log.Warningf("invalid prometheus_target_label: %s, target_id: %d", l, tg.ID)
			continue
		}
		labelNameToValue[k] = v
	}
	return
}

func (t *target) load() ([]*mysql.PrometheusTarget, error) {
	var targets []*mysql.PrometheusTarget
	err := mysql.Db.Find(&targets).Error
	return targets, err
}
