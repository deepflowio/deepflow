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
	MetricName string
	LabelName  string
}

func NewLayoutKey(metricName, labelName string) LayoutKey {
	return LayoutKey{
		MetricName: metricName,
		LabelName:  labelName,
	}
}

type metricAndAPPLabelLayout struct {
	layoutKeyToIndex          sync.Map
	metricNameToAPPLabelNames map[string][]string // only for fully assembled
}

func (t *metricAndAPPLabelLayout) Get() map[string][]string {
	return t.metricNameToAPPLabelNames
}

func (t *metricAndAPPLabelLayout) clear() {
	t.metricNameToAPPLabelNames = make(map[string][]string)
}

func (t *metricAndAPPLabelLayout) GetIndex(key LayoutKey) (uint8, bool) {
	if index, ok := t.layoutKeyToIndex.Load(key); ok {
		return index.(uint8), true
	}
	return 0, false
}

func (t *metricAndAPPLabelLayout) setIndex(key LayoutKey, index uint8) {
	t.layoutKeyToIndex.Store(key, index)
}

func (t *metricAndAPPLabelLayout) Add(batch []*controller.PrometheusMetricAPPLabelLayout) {
	for _, m := range batch {
		t.layoutKeyToIndex.Store(NewLayoutKey(m.GetMetricName(), m.GetAppLabelName()), uint8(m.GetAppLabelColumnIndex()))
	}
}

func (t *metricAndAPPLabelLayout) refresh(args ...interface{}) error {
	metricAPPLabelLayouts, err := t.load()
	if err != nil {
		return err
	}
	fully := args[0].(bool)
	if fully {
		for _, l := range metricAPPLabelLayouts {
			t.layoutKeyToIndex.Store(NewLayoutKey(l.MetricName, l.APPLabelName), uint8(l.APPLabelColumnIndex))
			t.metricNameToAPPLabelNames[l.MetricName] = append(t.metricNameToAPPLabelNames[l.MetricName], l.APPLabelName)
		}
	} else {
		for _, l := range metricAPPLabelLayouts {
			t.layoutKeyToIndex.Store(NewLayoutKey(l.MetricName, l.APPLabelName), uint8(l.APPLabelColumnIndex))
		}
	}
	return nil
}

func (t *metricAndAPPLabelLayout) load() ([]*mysql.PrometheusMetricAPPLabelLayout, error) {
	var metricAPPLabelLayouts []*mysql.PrometheusMetricAPPLabelLayout
	err := mysql.Db.Find(&metricAPPLabelLayouts).Error
	return metricAPPLabelLayouts, err
}
