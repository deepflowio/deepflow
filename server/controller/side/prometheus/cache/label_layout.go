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
	LabelValue string `json:"label_value"`
}

func NewLayoutKey(metricName, labelName, labelValue string) LayoutKey {
	return LayoutKey{
		MetricName: metricName,
		LabelName:  labelName,
		LabelValue: labelValue,
	}
}

type appLabelNameToValue map[string]string

type metricAndAPPLabelLayout struct {
	layoutKeyToIndex                sync.Map
	metricNameToAPPLabelNameToValue map[string]appLabelNameToValue // only for fully assembled
}

func (t *metricAndAPPLabelLayout) GetAPPLabelNameToValueByMetricName(n string) appLabelNameToValue {
	return t.metricNameToAPPLabelNameToValue[n]
}

func (t *metricAndAPPLabelLayout) GetIndexByLayoutKey(key LayoutKey) (uint8, bool) {
	if index, ok := t.layoutKeyToIndex.Load(key); ok {
		return index.(uint8), true
	}
	return 0, false
}

func (t *metricAndAPPLabelLayout) Add(batch []*controller.PrometheusMetricAPPLabelLayout) {
	for _, m := range batch {
		t.layoutKeyToIndex.Store(NewLayoutKey(m.GetMetricName(), m.GetAppLabelName(), m.GetAppLabelValue()), uint8(m.GetAppLabelColumnIndex()))
	}
}

func (t *metricAndAPPLabelLayout) clear() {
	t.metricNameToAPPLabelNameToValue = make(map[string]appLabelNameToValue)
}

func (t *metricAndAPPLabelLayout) refresh(args ...interface{}) error {
	metricAPPLabelLayouts, err := t.load()
	if err != nil {
		return err
	}
	fully := args[0].(bool)
	for _, l := range metricAPPLabelLayouts {
		if fully {
			if _, ok := t.metricNameToAPPLabelNameToValue[l.MetricName]; !ok {
				t.metricNameToAPPLabelNameToValue[l.MetricName] = make(appLabelNameToValue)
			}
			t.metricNameToAPPLabelNameToValue[l.MetricName][l.APPLabelName] = l.APPLabelValue
		}
		t.layoutKeyToIndex.Store(NewLayoutKey(l.MetricName, l.APPLabelName, l.APPLabelValue), uint8(l.APPLabelColumnIndex))
	}
	return nil
}

func (t *metricAndAPPLabelLayout) load() ([]*mysql.PrometheusMetricAPPLabelLayout, error) {
	var metricAPPLabelLayouts []*mysql.PrometheusMetricAPPLabelLayout
	err := mysql.Db.Find(&metricAPPLabelLayouts).Error
	return metricAPPLabelLayouts, err
}
