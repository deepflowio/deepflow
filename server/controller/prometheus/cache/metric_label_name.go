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
	"fmt"

	"github.com/cornelk/hashmap"
	mapset "github.com/deckarep/golang-set/v2"
	cmap "github.com/orcaman/concurrent-map/v2"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type metricLabelNameKey struct {
	metricID    int
	labelNameID int
}

func NewMetricLabelNameKey(metricID, labelNameID int) metricLabelNameKey {
	return metricLabelNameKey{
		metricID:    metricID,
		labelNameID: labelNameID,
	}
}

func (k metricLabelNameKey) String() string {
	return fmt.Sprintf("%d_%d", k.metricID, k.labelNameID)
}

type metricLabelName struct {
	metricNameCache *metricName

	metricNameIDToLabelNameIDs *hashmap.Map[int, mapset.Set[int]]
	keyToID                    cmap.ConcurrentMap[metricLabelNameKey, int]
}

func newMetricLabelName(mn *metricName) *metricLabelName {
	return &metricLabelName{
		metricNameCache: mn,

		metricNameIDToLabelNameIDs: hashmap.New[int, mapset.Set[int]](),
		keyToID:                    cmap.NewStringer[metricLabelNameKey, int](),
	}
}

func (ml *metricLabelName) IfLinked(metricID, labelNameID int) bool {
	if labelIDs, ok := ml.metricNameIDToLabelNameIDs.Get(metricID); ok {
		return labelIDs.(mapset.Set[int]).Contains(labelNameID)
	}
	return false
}

func (ml *metricLabelName) GetLabelNameIDsByMetricName(metricName string) []int {
	mni, ok := ml.metricNameCache.GetIDByName(metricName)
	if !ok {
		log.Debugf("metric_name: %s id not found", metricName)
		return nil
	}
	if labelNameIDs, ok := ml.metricNameIDToLabelNameIDs.Get(mni); ok {
		return labelNameIDs.ToSlice()
	}
	log.Debugf("metric_name: %s label_ids not found", metricName)
	return []int{}
}

func (mi *metricLabelName) GetMetricNameIDToLabelNameIDs() *hashmap.Map[int, mapset.Set[int]] {
	return mi.metricNameIDToLabelNameIDs
}

func (ml *metricLabelName) GetIDByKey(key metricLabelNameKey) (int, bool) {
	if id, ok := ml.keyToID.Get(key); ok {
		return id, true
	}
	return 0, false
}

func (ml *metricLabelName) Add(batch []*controller.PrometheusMetricLabelName) {
	for _, item := range batch {
		for _, li := range item.GetLabelNameIds() {
			mni := int(item.GetMetricNameId())
			ml.metricNameIDToLabelNameIDs.GetOrInsert(mni, mapset.NewSet[int]())
			if lids, ok := ml.metricNameIDToLabelNameIDs.Get(mni); ok {
				lids.Add(int(li))
			}
		}
	}
}

func (ml *metricLabelName) refresh(args ...interface{}) error {
	metricLabelNames, err := ml.load()
	if err != nil {
		return err
	}
	for _, item := range metricLabelNames {
		if mni, ok := ml.metricNameCache.GetIDByName(item.MetricName); ok {
			ml.metricNameIDToLabelNameIDs.GetOrInsert(mni, mapset.NewSet[int]())
			if lids, ok := ml.metricNameIDToLabelNameIDs.Get(mni); ok {
				lids.Add(item.LabelNameID)
			}
			ml.keyToID.Set(NewMetricLabelNameKey(mni, item.LabelNameID), item.ID)
		}
	}
	return nil
}

func (ml *metricLabelName) load() ([]*mysql.PrometheusMetricLabelName, error) {
	var items []*mysql.PrometheusMetricLabelName
	err := mysql.Db.Select("metric_name", "label_name_id", "id").Find(&items).Error
	return items, err
}
