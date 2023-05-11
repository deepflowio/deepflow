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

package encoder

import (
	"sync"

	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type labelLayout struct {
	mux                          sync.Mutex
	resourceType                 string
	metricNameToLabelNameToIndex map[string]map[string]uint8
	metricNameToMaxIndex         map[string]uint8
}

func newLabelLayout() *labelLayout {
	return &labelLayout{
		resourceType:                 "metric_app_label_layout",
		metricNameToLabelNameToIndex: make(map[string]map[string]uint8),
		metricNameToMaxIndex:         make(map[string]uint8),
	}
}

func (ll *labelLayout) refresh(args ...interface{}) error {
	ll.mux.Lock()
	defer ll.mux.Unlock()

	var layouts []*mysql.PrometheusMetricAPPLabelLayout
	err := mysql.Db.Find(&layouts).Error
	if err != nil {
		return err
	}

	for _, item := range layouts {
		if _, ok := ll.metricNameToLabelNameToIndex[item.MetricName]; !ok {
			ll.metricNameToLabelNameToIndex[item.MetricName] = make(map[string]uint8)
		}
		ll.metricNameToLabelNameToIndex[item.MetricName][item.APPLabelName] = item.APPLabelColumnIndex
		if ll.metricNameToMaxIndex[item.MetricName] < item.APPLabelColumnIndex {
			ll.metricNameToMaxIndex[item.MetricName] = item.APPLabelColumnIndex
		}
	}
	return nil
}

func (ll *labelLayout) sync(req []*controller.PrometheusMetricAPPLabelLayoutRequest) ([]*controller.PrometheusMetricAPPLabelLayout, error) {
	ll.mux.Lock()
	defer ll.mux.Unlock()

	resp := make([]*controller.PrometheusMetricAPPLabelLayout, 0, len(req))

	tmpMetricNameToMaxIndex := make(map[string]uint8)
	for k, v := range ll.metricNameToMaxIndex {
		tmpMetricNameToMaxIndex[k] = v
	}
	var dbToAdd []*mysql.PrometheusMetricAPPLabelLayout
	for _, v := range req {
		mn := v.GetMetricName()
		ln := v.GetAppLabelName()
		if _, ok := ll.metricNameToLabelNameToIndex[mn][ln]; ok {
			resp = append(resp, &controller.PrometheusMetricAPPLabelLayout{
				MetricName:          &mn,
				AppLabelName:        &ln,
				AppLabelColumnIndex: proto.Uint32(uint32(ll.metricNameToLabelNameToIndex[mn][ln])),
			})
		}
		dbToAdd = append(dbToAdd, &mysql.PrometheusMetricAPPLabelLayout{
			MetricName:          mn,
			APPLabelName:        ln,
			APPLabelColumnIndex: tmpMetricNameToMaxIndex[mn] + 1,
		})
		tmpMetricNameToMaxIndex[mn]++
	}
	err := addBatch(dbToAdd, ll.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", ll.resourceType, err.Error())
		return nil, err
	}
	for _, l := range dbToAdd {
		resp = append(resp, &controller.PrometheusMetricAPPLabelLayout{
			MetricName:          &l.MetricName,
			AppLabelName:        &l.APPLabelName,
			AppLabelColumnIndex: proto.Uint32(uint32(l.APPLabelColumnIndex)),
		})
		if _, ok := ll.metricNameToLabelNameToIndex[l.MetricName]; !ok {
			ll.metricNameToLabelNameToIndex[l.MetricName] = make(map[string]uint8)
		}
		ll.metricNameToLabelNameToIndex[l.MetricName][l.APPLabelName] = l.APPLabelColumnIndex
		if ll.metricNameToMaxIndex[l.MetricName] < l.APPLabelColumnIndex {
			ll.metricNameToMaxIndex[l.MetricName] = l.APPLabelColumnIndex
		}
	}
	return resp, nil
}
