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

package allocator

import (
	"sync"

	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type labelIndex struct {
	mux                          sync.Mutex
	metricNameToLabelNameToIndex map[string]map[string]uint8
}

func newLabelIndex() *labelIndex {
	return &labelIndex{
		metricNameToLabelNameToIndex: make(map[string]map[string]uint8),
	}
}

func (m *labelIndex) refresh() error {
	m.mux.Lock()
	defer m.mux.Unlock()

	var layouts []mysql.PrometheusMetricAPPLabelLayout
	err := mysql.Db.Find(&layouts).Error
	if err != nil {
		return err
	}

	for _, v := range layouts {
		if _, ok := m.metricNameToLabelNameToIndex[v.MetricName]; !ok {
			m.metricNameToLabelNameToIndex[v.MetricName] = make(map[string]uint8)
		}
		m.metricNameToLabelNameToIndex[v.MetricName][v.APPLabelName] = v.APPLabelColumnIndex
	}
	return nil
}

func (m *labelIndex) allocate(idxs []*controller.PrometheusAPPLabelIndexRequest) ([]*controller.PrometheusAPPLabelIndexesResponse, error) {
	m.mux.Lock()
	defer m.mux.Unlock()

	respIdxs := make([]*controller.PrometheusAPPLabelIndexesResponse, 0, len(idxs))
	for _, v := range idxs {
		mn := v.GetMetricName()
		ln := v.GetAppLabelName()
		idx, ok := m.metricNameToLabelNameToIndex[mn][ln]
		if !ok {
			idx = uint8(len(m.metricNameToLabelNameToIndex[mn])) + 1
			if _, ok := m.metricNameToLabelNameToIndex[mn]; !ok {
				m.metricNameToLabelNameToIndex[mn] = make(map[string]uint8)
			}
			m.metricNameToLabelNameToIndex[mn][ln] = idx
		}
		respIdx := &controller.PrometheusAPPLabelIndexesResponse{
			MetricName:          &mn,
			AppLabelName:        &ln,
			AppLabelColumnIndex: proto.Uint32(uint32(idx)),
		}
		respIdxs = append(respIdxs, respIdx)
	}
	return respIdxs, nil
}
