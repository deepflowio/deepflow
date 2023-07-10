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

type keyToTargetID struct {
	lock sync.Mutex
	data map[TargetKey]int
}

func newKeyToTargetID() *keyToTargetID {
	return &keyToTargetID{data: make(map[TargetKey]int)}
}

func (k *keyToTargetID) Load(tk TargetKey) (int, bool) {
	k.lock.Lock()
	defer k.lock.Unlock()
	id, ok := k.data[tk]
	return id, ok
}

func (k *keyToTargetID) Get() map[TargetKey]int {
	k.lock.Lock()
	defer k.lock.Unlock()
	return k.data
}

func (k *keyToTargetID) Coverage(data map[TargetKey]int) {
	k.lock.Lock()
	defer k.lock.Unlock()
	k.data = data
}

type targetLabelKeys struct {
	lock sync.Mutex
	data mapset.Set[TargetLabelKey]
}

func newTargetLabelKeys() *targetLabelKeys {
	return &targetLabelKeys{data: mapset.NewThreadUnsafeSet[TargetLabelKey]()}
}

func (t *targetLabelKeys) Contains(tlk TargetLabelKey) bool {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.data.Contains(tlk)
}

func (t *targetLabelKeys) Get() mapset.Set[TargetLabelKey] {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.data
}

func (t *targetLabelKeys) Coverage(data mapset.Set[TargetLabelKey]) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.data = data
}

type target struct {
	keyToTargetID   *keyToTargetID
	targetLabelKeys *targetLabelKeys
}

func newTarget() *target {
	return &target{
		keyToTargetID:   newKeyToTargetID(),
		targetLabelKeys: newTargetLabelKeys(),
	}
}

func (t *target) Get() map[TargetKey]int {
	return t.keyToTargetID.Get()
}

func (t *target) IfTargetLabelKeyExists(key TargetLabelKey) bool {
	return t.targetLabelKeys.Contains(key)
}

func (t *target) GetIDByKey(key TargetKey) (int, bool) {
	return t.keyToTargetID.Load(key)
}

func (t *target) refresh(args ...interface{}) error {
	targets, err := t.load()
	if err != nil {
		return err
	}
	keyToTargetID := make(map[TargetKey]int)
	targetLabelKeys := mapset.NewThreadUnsafeSet[TargetLabelKey]()
	for _, item := range targets {
		keyToTargetID[NewTargetKey(item.Instance, item.Job)] = item.ID
		for _, ln := range t.getTargetLabelNames(item) {
			targetLabelKeys.Add(NewTargetLabelKey(item.ID, ln))
		}
	}
	t.keyToTargetID.Coverage(keyToTargetID)
	t.targetLabelKeys.Coverage(targetLabelKeys)
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
