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
	"sync/atomic"

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
	org    *common.ORG
	active atomic.Value // map[LayoutKey]uint8

	mu      sync.RWMutex
	pending map[LayoutKey]uint8
}

func newMetricAndAPPLabelLayout(org *common.ORG) *metricAndAPPLabelLayout {
	mll := &metricAndAPPLabelLayout{
		org:     org,
		pending: make(map[LayoutKey]uint8),
	}
	mll.active.Store(make(map[LayoutKey]uint8))
	return mll
}

func (mll *metricAndAPPLabelLayout) getActive() map[LayoutKey]uint8 {
	if active := mll.active.Load(); active != nil {
		return active.(map[LayoutKey]uint8)
	}
	return map[LayoutKey]uint8{}
}

func (mll *metricAndAPPLabelLayout) replaceActive(newActive map[LayoutKey]uint8) {
	mll.active.Store(newActive)
}

func (mll *metricAndAPPLabelLayout) GetIndexByKey(key LayoutKey) (uint8, bool) {
	if index, ok := mll.getActive()[key]; ok {
		return index, true
	}
	mll.mu.RLock()
	defer mll.mu.RUnlock()
	index, ok := mll.pending[key]
	return index, ok
}

func (mll *metricAndAPPLabelLayout) GetLayoutKeyToIndex() map[LayoutKey]uint8 {
	active := mll.getActive()
	mll.mu.RLock()
	snapshot := make(map[LayoutKey]uint8, len(active)+len(mll.pending))
	for k, v := range active {
		snapshot[k] = v
	}
	for k, v := range mll.pending {
		snapshot[k] = v
	}
	mll.mu.RUnlock()
	return snapshot
}

func (mll *metricAndAPPLabelLayout) Add(batch []*metadbmodel.PrometheusMetricAPPLabelLayout) {
	mll.mu.Lock()
	defer mll.mu.Unlock()
	for _, m := range batch {
		mll.pending[NewLayoutKey(m.MetricName, m.APPLabelName)] = uint8(m.APPLabelColumnIndex)
	}
}

func (mll *metricAndAPPLabelLayout) AddFromGrpc(batch []*controller.PrometheusMetricAPPLabelLayout) {
	mll.mu.Lock()
	defer mll.mu.Unlock()
	for _, m := range batch {
		mll.pending[NewLayoutKey(m.GetMetricName(), m.GetAppLabelName())] = uint8(m.GetAppLabelColumnIndex())
	}
}

func (mll *metricAndAPPLabelLayout) refresh(args ...interface{}) error {
	var count int64
	if err := mll.org.DB.Model(&metadbmodel.PrometheusMetricAPPLabelLayout{}).Count(&count).Error; err != nil {
		return err
	}

	rows, err := mll.org.DB.Model(&metadbmodel.PrometheusMetricAPPLabelLayout{}).Select("metric_name", "app_label_name", "app_label_column_index").Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	newActive := make(map[LayoutKey]uint8, count)
	for rows.Next() {
		var metricName string
		var appLabelName string
		var appLabelColumnIndex int
		if scanErr := rows.Scan(&metricName, &appLabelName, &appLabelColumnIndex); scanErr != nil {
			log.Errorf("stream scan prometheus_metric_app_label_layout interrupted: %v", scanErr, mll.org.LogPrefix)
			return scanErr
		}
		newActive[NewLayoutKey(metricName, appLabelName)] = uint8(appLabelColumnIndex)
	}
	if err := rows.Err(); err != nil {
		log.Errorf("stream read prometheus_metric_app_label_layout error: %v", err, mll.org.LogPrefix)
		return err
	}

	mll.mu.Lock()
	pending := mll.pending
	mll.pending = make(map[LayoutKey]uint8)
	mll.mu.Unlock()

	for k, v := range pending {
		newActive[k] = v
	}
	mll.replaceActive(newActive)
	return nil
}
