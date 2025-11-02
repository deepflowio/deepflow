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

package encoder

import (
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"google.golang.org/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

type metricLabelNameKey struct {
	MetricNameID int
	LabelNameID  int
}

func newMetricLabelNameKey(metricNameID, labelNameID int) metricLabelNameKey {
	return metricLabelNameKey{
		MetricNameID: metricNameID,
		LabelNameID:  labelNameID,
	}
}

type metricLabelName struct {
	org          *common.ORG
	lock         sync.Mutex
	resourceType string

	metricNameEncoder *metricName
	labelNameEncoder  *labelName

	keys mapset.Set[metricLabelNameKey]
}

func newMetricLabelName(org *common.ORG, mn *metricName, l *labelName) *metricLabelName {
	return &metricLabelName{
		org:               org,
		resourceType:      "metric_label",
		metricNameEncoder: mn,
		labelNameEncoder:  l,
		keys:              mapset.NewSet[metricLabelNameKey](),
	}
}

func (ml *metricLabelName) store(item *mysqlmodel.PrometheusMetricLabelName) {
	if mni, ok := ml.metricNameEncoder.getID(item.MetricName); ok {
		ml.keys.Add(newMetricLabelNameKey(mni, item.LabelNameID))
	}
}

func (ml *metricLabelName) refresh(args ...interface{}) error {
	var items []*mysqlmodel.PrometheusMetricLabelName
	err := ml.org.DB.Find(&items).Error
	if err != nil {
		return err
	}
	for _, item := range items {
		ml.store(item)
	}
	return nil
}

func (ml *metricLabelName) encode(rMLs []*controller.PrometheusMetricLabelNameRequest) ([]*controller.PrometheusMetricLabelName, error) {
	ml.lock.Lock()
	defer ml.lock.Unlock()

	resp := make([]*controller.PrometheusMetricLabelName, 0)
	var dbToAdd []*mysqlmodel.PrometheusMetricLabelName
	respToAdd := make([]*controller.PrometheusMetricLabelName, 0)
	for _, rML := range rMLs {
		mn := rML.GetMetricName()
		mni, ok := ml.metricNameEncoder.getID(mn)
		if !ok {
			log.Warningf("%s metric_name: %s id not found", ml.resourceType, mn, ml.org.LogPrefix)
			continue
		}
		lis := make([]uint32, 0)
		lisToAdd := make([]uint32, 0)
		for _, ln := range rML.GetLabelNames() {
			lni, ok := ml.labelNameEncoder.getID(ln)
			if !ok {
				log.Warningf("%s label (name: %s) id not found", ml.resourceType, ln, ml.org.LogPrefix)
				continue
			}
			if ok := ml.keys.Contains(newMetricLabelNameKey(mni, lni)); ok {
				lis = append(lis, uint32(lni))
				continue
			}
			dbToAdd = append(dbToAdd, &mysqlmodel.PrometheusMetricLabelName{
				MetricName:  mn,
				LabelNameID: lni,
			})
			lisToAdd = append(lisToAdd, uint32(lni))
		}
		if len(lis) != 0 {
			resp = append(resp, &controller.PrometheusMetricLabelName{
				MetricNameId: proto.Uint32(uint32(mni)),
				LabelNameIds: lis,
			})
		}
		if len(lisToAdd) != 0 {
			respToAdd = append(respToAdd, &controller.PrometheusMetricLabelName{
				MetricNameId: proto.Uint32(uint32(mni)),
				LabelNameIds: lisToAdd,
			})
		}
	}
	err := addBatch(ml.org.DB, dbToAdd, ml.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", ml.resourceType, err.Error(), ml.org.LogPrefix)
		return resp, err
	}
	for _, item := range dbToAdd {
		ml.store(item)
	}
	return append(resp, respToAdd...), nil
}
