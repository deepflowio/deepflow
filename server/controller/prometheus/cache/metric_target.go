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
	mapset "github.com/deckarep/golang-set/v2"

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

type metricTarget struct {
	metricNameCache     *metricName
	metricTargetKeys    mapset.Set[MetricTargetKey]
	targetIDToMetricIDs map[int][]uint32 // only for fully assembled
}

func newMetricTarget(c *metricName) *metricTarget {
	return &metricTarget{
		metricNameCache:     c,
		metricTargetKeys:    mapset.NewSet[MetricTargetKey](),
		targetIDToMetricIDs: make(map[int][]uint32),
	}
}

func (mt *metricTarget) IfKeyExists(k MetricTargetKey) bool {
	return mt.metricTargetKeys.Contains(k)
}

func (mt *metricTarget) GetMetricIDsByTargetID(id int) []uint32 {
	return mt.targetIDToMetricIDs[id]
}

func (mt *metricTarget) Add(batch []MetricTargetKey) {
	for _, item := range batch {
		mt.metricTargetKeys.Add(item)
	}
}

func (mt *metricTarget) refresh(args ...interface{}) error {
	mts, err := mt.load()
	if err != nil {
		return err
	}
	targetIDToMetricIDs := make(map[int][]uint32)
	for _, item := range mts {
		mt.metricTargetKeys.Add(NewMetricTargetKey(item.MetricName, item.TargetID))
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
