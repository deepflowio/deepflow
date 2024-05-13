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
	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
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
	lock         sync.Mutex
	resourceType string

	metricNameEncoder *metricName
	labelNameEncoder  *labelName

	keys mapset.Set[metricLabelNameKey]
}

func newMetricLabelName(mn *metricName, l *labelName) *metricLabelName {
	return &metricLabelName{
		resourceType:      "metric_label",
		metricNameEncoder: mn,
		labelNameEncoder:  l,
		keys:              mapset.NewSet[metricLabelNameKey](),
	}
}

func (ml *metricLabelName) store(item *mysql.PrometheusMetricLabelName) {
	if mni, ok := ml.metricNameEncoder.getID(item.MetricName); ok {
		ml.keys.Add(newMetricLabelNameKey(mni, item.LabelNameID))
	}
}

func (ml *metricLabelName) refresh(args ...interface{}) error {
	log.Infof("refresh %s", ml.resourceType)
	var items []*mysql.PrometheusMetricLabelName
	err := mysql.Db.Find(&items).Error
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
	var dbToAdd []*mysql.PrometheusMetricLabelName
	respToAdd := make([]*controller.PrometheusMetricLabelName, 0)
	for _, rML := range rMLs {
		mn := rML.GetMetricName()
		mni, ok := ml.metricNameEncoder.getID(mn)
		if !ok {
			log.Warningf("%s metric_name: %s id not found", ml.resourceType, mn)
			continue
		}
		lis := make([]uint32, 0)
		lisToAdd := make([]uint32, 0)
		for _, ln := range rML.GetLabelNames() {
			lni, ok := ml.labelNameEncoder.getID(ln)
			if !ok {
				log.Warningf("%s label (name: %s) id not found", ml.resourceType, ln)
				continue
			}
			if ok := ml.keys.Contains(newMetricLabelNameKey(mni, lni)); ok {
				lis = append(lis, uint32(lni))
				continue
			}
			dbToAdd = append(dbToAdd, &mysql.PrometheusMetricLabelName{
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
	err := addBatch(dbToAdd, ml.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", ml.resourceType, err.Error())
		return resp, err
	}
	for _, item := range dbToAdd {
		ml.store(item)
	}
	return append(resp, respToAdd...), nil
}
