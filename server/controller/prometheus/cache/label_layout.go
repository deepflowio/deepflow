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

	"github.com/deepflowio/deepflow/message/controller"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

type LayoutKey struct {
	MetricName string `json:"metric_name"`
	LabelName  string `json:"label_name"`
}

func (k LayoutKey) String() string {
	return k.MetricName + "-" + k.LabelName
}

func NewLayoutKey(metricName, labelName string) LayoutKey {
	return LayoutKey{
		MetricName: metricName,
		LabelName:  labelName,
	}
}

type appLabelNameToValue map[string]string
type metricAndAPPLabelLayout struct {
	org *common.ORG

	mu               sync.RWMutex
	layoutKeyToIndex map[LayoutKey]uint8
}

func newMetricAndAPPLabelLayout(org *common.ORG) *metricAndAPPLabelLayout {
	return &metricAndAPPLabelLayout{
		org:              org,
		layoutKeyToIndex: make(map[LayoutKey]uint8),
	}
}

// GetLayoutKeyToIndex returns a snapshot copy of the layoutKeyToIndex map.
func (mll *metricAndAPPLabelLayout) GetLayoutKeyToIndex() map[LayoutKey]uint8 {
	mll.mu.RLock()
	defer mll.mu.RUnlock()
	result := make(map[LayoutKey]uint8, len(mll.layoutKeyToIndex))
	for k, v := range mll.layoutKeyToIndex {
		result[k] = v
	}
	return result
}

func (mll *metricAndAPPLabelLayout) GetIndexByKey(key LayoutKey) (uint8, bool) {
	mll.mu.RLock()
	defer mll.mu.RUnlock()
	index, ok := mll.layoutKeyToIndex[key]
	return index, ok
}

func (mll *metricAndAPPLabelLayout) Add(batch []*controller.PrometheusMetricAPPLabelLayout) {
	mll.mu.Lock()
	defer mll.mu.Unlock()
	for _, m := range batch {
		mll.layoutKeyToIndex[NewLayoutKey(m.GetMetricName(), m.GetAppLabelName())] = uint8(m.GetAppLabelColumnIndex())
	}
}

// refresh rebuilds the entire cache from DB (snapshot-and-swap).
func (mll *metricAndAPPLabelLayout) refresh(args ...interface{}) error {
	metricAPPLabelLayouts, err := mll.load()
	if err != nil {
		return err
	}
	newMap := make(map[LayoutKey]uint8, len(metricAPPLabelLayouts))
	for _, l := range metricAPPLabelLayouts {
		newMap[NewLayoutKey(l.MetricName, l.APPLabelName)] = uint8(l.APPLabelColumnIndex)
	}
	mll.mu.Lock()
	mll.layoutKeyToIndex = newMap
	mll.mu.Unlock()
	return nil
}

func (mml *metricAndAPPLabelLayout) load() ([]*metadbmodel.PrometheusMetricAPPLabelLayout, error) {
	var metricAPPLabelLayouts []*metadbmodel.PrometheusMetricAPPLabelLayout
	err := mml.org.DB.Select("metric_name", "app_label_name", "app_label_column_index").Find(&metricAPPLabelLayouts).Error
	return metricAPPLabelLayouts, err
}
