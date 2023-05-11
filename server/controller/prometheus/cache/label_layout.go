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
	"sync"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type LayoutKey struct {
	MetricName string `json:"metric_name"`
	LabelName  string `json:"label_name"`
}

func NewLayoutKey(metricName, labelName string) LayoutKey {
	return LayoutKey{
		MetricName: metricName,
		LabelName:  labelName,
	}
}

type appLabelNameToValue map[string]string

type metricAndAPPLabelLayout struct {
	layoutKeyToIndex                sync.Map
	metricNameToAPPLabelNameToValue map[string]appLabelNameToValue // only for fully assembled
}

func (mll *metricAndAPPLabelLayout) GetLabelNameToValueByMetricName(n string) appLabelNameToValue {
	return mll.metricNameToAPPLabelNameToValue[n]
}

func (mll *metricAndAPPLabelLayout) GetIndexByKey(key LayoutKey) (uint8, bool) {
	if index, ok := mll.layoutKeyToIndex.Load(key); ok {
		return index.(uint8), true
	}
	return 0, false
}

func (mll *metricAndAPPLabelLayout) Add(batch []*controller.PrometheusMetricAPPLabelLayout) {
	for _, m := range batch {
		mll.layoutKeyToIndex.Store(NewLayoutKey(m.GetMetricName(), m.GetAppLabelName()), uint8(m.GetAppLabelColumnIndex()))
	}
}

func (mll *metricAndAPPLabelLayout) clear() {
	mll.metricNameToAPPLabelNameToValue = make(map[string]appLabelNameToValue)
}

func (mll *metricAndAPPLabelLayout) refresh(args ...interface{}) error {
	metricAPPLabelLayouts, err := mll.load()
	if err != nil {
		return err
	}
	fully := args[0].(bool)
	for _, l := range metricAPPLabelLayouts {
		if fully {
			if _, ok := mll.metricNameToAPPLabelNameToValue[l.MetricName]; !ok {
				mll.metricNameToAPPLabelNameToValue[l.MetricName] = make(appLabelNameToValue)
			}
		}
		mll.layoutKeyToIndex.Store(NewLayoutKey(l.MetricName, l.APPLabelName), uint8(l.APPLabelColumnIndex))
	}
	return nil
}

func (mml *metricAndAPPLabelLayout) load() ([]*mysql.PrometheusMetricAPPLabelLayout, error) {
	var metricAPPLabelLayouts []*mysql.PrometheusMetricAPPLabelLayout
	err := mysql.Db.Find(&metricAPPLabelLayouts).Error
	return metricAPPLabelLayouts, err
}
