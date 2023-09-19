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
	"sort"
	"strings"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

var (
	labelJoiner   = ", "
	labelKVJoiner = ":"
)

type TargetKey struct {
	Instance     string
	Job          string
	PodClusterID int
}

func NewTargetKey(instance, job string, podClusterID int) TargetKey {
	return TargetKey{
		Instance:     instance,
		Job:          job,
		PodClusterID: podClusterID,
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

func (k *keyToTargetID) Store(tk TargetKey, v int) {
	k.lock.Lock()
	defer k.lock.Unlock()
	k.data[tk] = v
}

func (k *keyToTargetID) Coverage(data map[TargetKey]int) {
	k.lock.Lock()
	defer k.lock.Unlock()
	k.data = data
}

type targetIDToLabelNames struct {
	lock sync.Mutex
	data map[int]mapset.Set[string]
}

func newTargetIDToLabelNames() *targetIDToLabelNames {
	return &targetIDToLabelNames{data: make(map[int]mapset.Set[string])}
}

func (t *targetIDToLabelNames) Contains(id int, labelName string) bool {
	t.lock.Lock()
	defer t.lock.Unlock()
	if set, ok := t.data[id]; ok {
		return set.Contains(labelName)
	}
	return false
}

func (t *targetIDToLabelNames) Get() map[int]mapset.Set[string] {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.data
}

func (t *targetIDToLabelNames) Coverage(data map[int]mapset.Set[string]) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.data = data
}

func (t *targetIDToLabelNames) Load(id int) []string {
	t.lock.Lock()
	defer t.lock.Unlock()
	set, ok := t.data[id]
	if ok {
		slice := set.ToSlice()
		sort.Strings(slice)
		return slice
	}
	return []string{}
}

type target struct {
	keyToTargetID        *keyToTargetID
	targetIDToLabelNames *targetIDToLabelNames
	idToLabels           sync.Map
}

func newTarget() *target {
	return &target{
		keyToTargetID:        newKeyToTargetID(),
		targetIDToLabelNames: newTargetIDToLabelNames(),
	}
}

func (t *target) Get() map[TargetKey]int {
	return t.keyToTargetID.Get()
}

func (t *target) IfLabelIsTargetType(id int, labelName string) bool {
	return t.targetIDToLabelNames.Contains(id, labelName)
}

func (t *target) GetIDByKey(key TargetKey) (int, bool) {
	return t.keyToTargetID.Load(key)
}

func (t *target) GetLabelNamesByID(id int) []string {
	return t.targetIDToLabelNames.Load(id)
}

func (t *target) Add(batch []*controller.PrometheusTarget) {
	for _, item := range batch {
		t.keyToTargetID.Store(NewTargetKey(item.GetInstance(), item.GetJob(), int(item.GetPodClusterId())), int(item.GetId()))
	}
}

func (t *target) GetTargetIDToLabelNames() map[int]mapset.Set[string] {
	return t.targetIDToLabelNames.Get()
}

func (t *target) refresh(args ...interface{}) error {
	recorderTargets, selfTargets, err := t.load()
	if err != nil {
		return err
	}

	keyToTargetID := make(map[TargetKey]int)
	targetIDToLabelNames := make(map[int]mapset.Set[string])
	for _, item := range recorderTargets {
		keyToTargetID[NewTargetKey(item.Instance, item.Job, item.PodClusterID)] = item.ID
		targetIDToLabelNames[item.ID] = mapset.NewSet(t.getTargetLabelNames(item)...)
	}

	dupKeyIDs := make([]int, 0)
	for _, item := range selfTargets {
		tk := NewTargetKey(item.Instance, item.Job, item.PodClusterID)
		if _, ok := keyToTargetID[tk]; ok {
			dupKeyIDs = append(dupKeyIDs, item.ID)
			continue
		}
		keyToTargetID[tk] = item.ID
		targetIDToLabelNames[item.ID] = mapset.NewSet(t.getTargetLabelNames(item)...)
	}
	if len(dupKeyIDs) != 0 {
		t.dedup(dupKeyIDs)
	}

	t.keyToTargetID.Coverage(keyToTargetID)
	t.targetIDToLabelNames.Coverage(targetIDToLabelNames)
	return nil
}

func (t *target) getTargetLabelNames(tg *mysql.PrometheusTarget) []string {
	lns := []string{TargetLabelInstance, TargetLabelJob}
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

func (t *target) load() (recorderTargets, selfTargets []*mysql.PrometheusTarget, err error) {
	err = mysql.Db.Where(&mysql.PrometheusTarget{CreateMethod: common.PROMETHEUS_TARGET_CREATE_METHOD_RECORDER}).Find(&recorderTargets).Error
	if err != nil {
		return
	}
	err = mysql.Db.Where(&mysql.PrometheusTarget{CreateMethod: common.PROMETHEUS_TARGET_CREATE_METHOD_PROMETHEUS}).Find(&selfTargets).Error
	return
}

func (t *target) dedup(ids []int) error {
	return mysql.Db.Where("id in (?)", ids).Delete(&mysql.PrometheusTarget{}).Error
}

type domainInfo struct {
	domain    string
	subDomain string
}

func newDomainInfo(domain, subDomain string) domainInfo {
	return domainInfo{
		domain:    domain,
		subDomain: subDomain,
	}
}
