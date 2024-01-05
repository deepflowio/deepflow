/**
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

package cache

import (
	"sync"

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type MetricTargetKey struct {
	MetricName string
	TargetID   int
}

func NewMetricTargetKey(metricName string, targetID int) MetricTargetKey {
	return MetricTargetKey{
		MetricName: metricName,
		TargetID:   targetID,
	}
}

type metricNameToTargetIDs struct {
	lock sync.Mutex
	data map[string]mapset.Set[int]
}

func newMetricNameToTargetIDs() *metricNameToTargetIDs {
	return &metricNameToTargetIDs{data: make(map[string]mapset.Set[int])}
}

func (k *metricNameToTargetIDs) Load(id string) (mapset.Set[int], bool) {
	k.lock.Lock()
	defer k.lock.Unlock()
	ids, ok := k.data[id]
	return ids, ok
}

func (k *metricNameToTargetIDs) Get() map[string]mapset.Set[int] {
	k.lock.Lock()
	defer k.lock.Unlock()
	data := make(map[string]mapset.Set[int])
	for k, v := range k.data {
		data[k] = v
	}
	return data
}

func (k *metricNameToTargetIDs) Append(name string, id int) {
	k.lock.Lock()
	defer k.lock.Unlock()
	if _, ok := k.data[name]; !ok {
		k.data[name] = mapset.NewSet[int]()
	}
	k.data[name].Add(id)
}

func (k *metricNameToTargetIDs) Coverage(data map[string]mapset.Set[int]) {
	k.lock.Lock()
	defer k.lock.Unlock()
	k.data = data
}

type metricTarget struct {
	metricNameCache *metricName
	targetCache     *target

	metricTargetKeys      mapset.Set[MetricTargetKey]
	metricNameToTargetIDs *metricNameToTargetIDs
	targetIDToMetricIDs   map[int][]uint32 // only for fully assembled
}

func newMetricTarget(mn *metricName, t *target) *metricTarget {
	return &metricTarget{
		metricNameCache: mn,
		targetCache:     t,

		metricTargetKeys:      mapset.NewSet[MetricTargetKey](),
		metricNameToTargetIDs: newMetricNameToTargetIDs(),
		targetIDToMetricIDs:   make(map[int][]uint32),
	}
}

func (mt *metricTarget) IfKeyExists(k MetricTargetKey) bool {
	return mt.metricTargetKeys.Contains(k)
}

func (mt *metricTarget) GetMetricIDsByTargetID(id int) []uint32 {
	return mt.targetIDToMetricIDs[id]
}

func (mt *metricTarget) Add(batch []*controller.PrometheusMetricTarget) {
	for _, item := range batch {
		mt.metricTargetKeys.Add(NewMetricTargetKey(item.GetMetricName(), int(item.GetTargetId())))
		mt.metricNameToTargetIDs.Append(item.GetMetricName(), int(item.GetTargetId()))
	}
}

func (mt *metricTarget) IfLabelIsTargetType(mn, ln string) bool {
	if tIDs, ok := mt.metricNameToTargetIDs.Load(mn); ok {
		for _, tID := range tIDs.ToSlice() {
			if mt.targetCache.IfLabelIsTargetType(tID, ln) {
				return true
			}
		}
	}
	return false
}

func (mt *metricTarget) GetMetricNameToTargetIDs() map[string]mapset.Set[int] {
	return mt.metricNameToTargetIDs.Get()
}

func (mt *metricTarget) refresh(args ...interface{}) error {
	mts, err := mt.load()
	if err != nil {
		return err
	}
	targetIDToMetricIDs := make(map[int][]uint32)
	for _, item := range mts {
		mt.metricTargetKeys.Add(NewMetricTargetKey(item.MetricName, item.TargetID))
		mt.metricNameToTargetIDs.Append(item.MetricName, item.TargetID)
		if mni, ok := mt.metricNameCache.GetIDByName(item.MetricName); ok {
			targetIDToMetricIDs[item.TargetID] = append(targetIDToMetricIDs[item.TargetID], uint32(mni))
		}
	}
	mt.targetIDToMetricIDs = targetIDToMetricIDs
	return nil
}

func (mt *metricTarget) load() ([]*mysql.PrometheusMetricTarget, error) {
	var metricTargets []*mysql.PrometheusMetricTarget
	err := mysql.Db.Find(&metricTargets).Error
	return metricTargets, err
}
