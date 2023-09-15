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
	"fmt"
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/golang/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	prometheuscfg "github.com/deepflowio/deepflow/server/controller/prometheus/config"
)

type indexAllocator struct {
	lock         sync.Mutex
	resourceType string
	metricName   string
	strToIdx     map[string]int
	ascIDAllocator
}

func newIndexAllocator(metricName string, max int) *indexAllocator {
	ia := &indexAllocator{
		resourceType: fmt.Sprintf("%s app_label_index", metricName),
		metricName:   metricName,
		strToIdx:     make(map[string]int),
	}
	ia.ascIDAllocator = newAscIDAllocator(ia.resourceType, 1, max)
	ia.rawDataProvider = ia
	return ia
}

func (ia *indexAllocator) refresh(labelNameToIdx map[string]int) error {
	ia.lock.Lock()
	defer ia.lock.Unlock()
	ia.strToIdx = labelNameToIdx
	return ia.ascIDAllocator.refresh()
}

func (ia *indexAllocator) load() (ids mapset.Set[int], err error) {
	inUseIdxSet := mapset.NewSet[int]()
	for _, idx := range ia.strToIdx {
		inUseIdxSet.Add(idx)
	}
	return inUseIdxSet, nil
}

func (ia *indexAllocator) encode(strs []string) ([]*controller.PrometheusMetricAPPLabelLayout, error) {
	ia.lock.Lock()
	defer ia.lock.Unlock()

	resp := make([]*controller.PrometheusMetricAPPLabelLayout, 0)
	var dbToAdd []*mysql.PrometheusMetricAPPLabelLayout
	for i := range strs {
		str := strs[i]
		if idx, ok := ia.strToIdx[str]; ok {
			resp = append(resp, &controller.PrometheusMetricAPPLabelLayout{MetricName: &ia.metricName, AppLabelName: &str, AppLabelColumnIndex: proto.Uint32(uint32(idx))})
			continue
		}
		dbToAdd = append(dbToAdd, &mysql.PrometheusMetricAPPLabelLayout{MetricName: ia.metricName, APPLabelName: str})
	}
	if len(dbToAdd) == 0 {
		return resp, nil
	}
	idxs, err := ia.allocate(len(dbToAdd))
	if err != nil {
		return nil, err
	}
	for i := range idxs {
		dbToAdd[i].APPLabelColumnIndex = uint8(idxs[i])
	}
	err = addBatch(dbToAdd, ia.resourceType)
	if err != nil {
		log.Errorf("add %s error: %s", ia.resourceType, err.Error())
		return nil, err
	}
	for i := range dbToAdd {
		idx := dbToAdd[i].APPLabelColumnIndex
		str := dbToAdd[i].APPLabelName
		ia.strToIdx[str] = int(idx)
		resp = append(resp, &controller.PrometheusMetricAPPLabelLayout{MetricName: &ia.metricName, AppLabelName: &str, AppLabelColumnIndex: proto.Uint32(uint32(idx))})
	}
	return resp, nil
}

func (ia *indexAllocator) check(ids []int) (inUseIDs []int, err error) {
	var dbItems []*mysql.PrometheusMetricAPPLabelLayout
	err = mysql.Db.Where("metric_name = ? AND app_label_column_index IN (?)", ia.metricName, ids).Find(&dbItems).Error
	if err != nil {
		log.Errorf("db query %s failed: %v", ia.resourceType, err)
		return
	}
	if len(dbItems) != 0 {
		for _, item := range dbItems {
			inUseIDs = append(inUseIDs, int(item.APPLabelColumnIndex))
		}
		log.Infof("%s ids: %+v are in use.", ia.resourceType, inUseIDs)
	}
	return
}

func (ia *indexAllocator) release(ids []int) error {
	ia.lock.Lock()
	defer ia.lock.Unlock()

	err := mysql.Db.Where("metric_name = ? AND app_label_column_index IN (?)", ia.metricName, ids).Delete(&mysql.PrometheusMetricAPPLabelLayout{}).Error
	if err != nil {
		return err
	}
	ia.recycle(ids)
	return nil
}

type labelLayout struct {
	appLabelIndexMax int

	lock                     sync.Mutex
	resourceType             string
	metricNameToIdxAllocator map[string]*indexAllocator
}

func newLabelLayout(cfg *prometheuscfg.Config) *labelLayout {
	return &labelLayout{
		appLabelIndexMax: cfg.APPLabelIndexMax,

		resourceType:             "metric_app_label_layout",
		metricNameToIdxAllocator: make(map[string]*indexAllocator),
	}
}

func (ll *labelLayout) refresh(args ...interface{}) error {
	var items []*mysql.PrometheusMetricAPPLabelLayout
	err := mysql.Db.Find(&items).Error
	if err != nil {
		return err
	}
	mnToLnIdx := make(map[string]map[string]int)
	for _, item := range items {
		if _, ok := mnToLnIdx[item.MetricName]; !ok {
			mnToLnIdx[item.MetricName] = make(map[string]int)
		}
		mnToLnIdx[item.MetricName][item.APPLabelName] = int(item.APPLabelColumnIndex)
	}

	for mn, lnToIdx := range mnToLnIdx {
		ia, _ := ll.createIndexAllocatorIfNotExists(mn)
		ia.refresh(lnToIdx)
	}
	for mn, ia := range ll.metricNameToIdxAllocator {
		if _, ok := mnToLnIdx[mn]; !ok {
			ia.refresh(make(map[string]int))
		}
	}
	return nil
}

func (ll *labelLayout) encode(req []*controller.PrometheusMetricAPPLabelLayoutRequest) ([]*controller.PrometheusMetricAPPLabelLayout, error) {
	mnToLNs := make(map[string][]string)
	for _, item := range req {
		mn := item.GetMetricName()
		if _, ok := mnToLNs[mn]; !ok {
			mnToLNs[mn] = make([]string, 0)
		}
		mnToLNs[mn] = append(mnToLNs[mn], item.GetAppLabelName())
	}

	resp := make([]*controller.PrometheusMetricAPPLabelLayout, 0)
	for mn, lns := range mnToLNs {
		layouts, err := ll.SingleEncode(mn, lns)
		if err != nil {
			return nil, err
		}
		resp = append(resp, layouts...)
	}
	return resp, nil
}

func (ll *labelLayout) createIndexAllocatorIfNotExists(metricName string) (*indexAllocator, error) {
	ll.lock.Lock()
	defer ll.lock.Unlock()
	if allocator, ok := ll.metricNameToIdxAllocator[metricName]; ok {
		return allocator, nil
	}
	ia := newIndexAllocator(metricName, ll.appLabelIndexMax)
	ia.refresh(make(map[string]int))
	ll.metricNameToIdxAllocator[metricName] = ia
	return ll.metricNameToIdxAllocator[metricName], nil
}

func (ll *labelLayout) getIndexAllocator(metricName string) (*indexAllocator, bool) {
	ll.lock.Lock()
	defer ll.lock.Unlock()
	allocator, ok := ll.metricNameToIdxAllocator[metricName]
	return allocator, ok
}

func (ll *labelLayout) SingleEncode(metricName string, labelNames []string) ([]*controller.PrometheusMetricAPPLabelLayout, error) {
	log.Infof("encode metric: %s app label names: %v", metricName, labelNames)
	ia, _ := ll.createIndexAllocatorIfNotExists(metricName)
	return ia.encode(labelNames)
}

func (ll *labelLayout) SingleRelease(metricName string, indexes []int) error {
	log.Infof("recycle metric: %s indexes: %v", metricName, indexes)
	if allocator, ok := ll.getIndexAllocator(metricName); ok {
		return allocator.release(indexes)
	}
	return nil
}
