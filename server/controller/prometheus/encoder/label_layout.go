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
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
)

type labelLayout struct {
	lock                 sync.Mutex
	resourceType         string
	layoutKeyToIndex     map[cache.LayoutKey]uint8
	metricNameToMaxIndex map[string]uint8
}

func newLabelLayout() *labelLayout {
	return &labelLayout{
		resourceType:         "metric_app_label_layout",
		layoutKeyToIndex:     make(map[cache.LayoutKey]uint8),
		metricNameToMaxIndex: make(map[string]uint8),
	}
}

func (ll *labelLayout) refresh(args ...interface{}) error {
	ll.lock.Lock()
	defer ll.lock.Unlock()

	var items []*mysql.PrometheusMetricAPPLabelLayout
	err := mysql.Db.Find(&items).Error
	if err != nil {
		return err
	}

	for _, item := range items {
		ll.layoutKeyToIndex[cache.NewLayoutKey(item.MetricName, item.APPLabelName)] = item.APPLabelColumnIndex
		if ll.metricNameToMaxIndex[item.MetricName] < item.APPLabelColumnIndex {
			ll.metricNameToMaxIndex[item.MetricName] = item.APPLabelColumnIndex
		}
	}
	return nil
}

func (ll *labelLayout) encode(req []*controller.PrometheusMetricAPPLabelLayoutRequest) ([]*controller.PrometheusMetricAPPLabelLayout, error) {
	ll.lock.Lock()
	defer ll.lock.Unlock()

	resp := make([]*controller.PrometheusMetricAPPLabelLayout, 0, len(req))

	tmpMetricNameToMaxIndex := make(map[string]uint8)
	for k, v := range ll.metricNameToMaxIndex {
		tmpMetricNameToMaxIndex[k] = v
	}
	var dbToAdd []*mysql.PrometheusMetricAPPLabelLayout
	for _, v := range req {
		mn := v.GetMetricName()
		ln := v.GetAppLabelName()
		if idx, ok := ll.layoutKeyToIndex[cache.NewLayoutKey(mn, ln)]; ok {
			resp = append(resp, &controller.PrometheusMetricAPPLabelLayout{
				MetricName:          &mn,
				AppLabelName:        &ln,
				AppLabelColumnIndex: proto.Uint32(uint32(idx)),
			})
			continue
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
		ll.layoutKeyToIndex[cache.NewLayoutKey(l.MetricName, l.APPLabelName)] = l.APPLabelColumnIndex
		if ll.metricNameToMaxIndex[l.MetricName] < l.APPLabelColumnIndex {
			ll.metricNameToMaxIndex[l.MetricName] = l.APPLabelColumnIndex
		}
	}
	return resp, nil
}
