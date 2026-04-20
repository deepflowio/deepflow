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

package prometheus

import (
	// "sort"
	"fmt"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"google.golang.org/protobuf/proto"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("prometheus.synchronizer")

const (
	maxLogCount = 10
	maxLogSize  = 64 * 1024 // 64KB
)

func logNotFoundDetail(items interface{}) string {
	logItems := items.([]interface{})
	if len(logItems) > maxLogCount {
		logItems = logItems[:maxLogCount]
	}
	logItemsStr := make([]string, 0, len(logItems))
	for _, item := range logItems {
		logItemsStr = append(logItemsStr, fmt.Sprintf("%v", item))
	}
	itemsStr := strings.Join(logItemsStr, ",")
	if len(itemsStr) > maxLogSize {
		itemsStr = itemsStr[:maxLogSize] + "... (truncated)"
	}
	return fmt.Sprintf("count: %d, <= %d items: %s", len(logItems), maxLogCount, itemsStr)
}

type counter struct {
	SendMetricCount uint64
	SendLabelCount  uint64
	SendTargetCount uint64
}

type Synchronizer struct {
	org     *common.ORG
	cache   *cache.Cache
	counter *counter
}

func newSynchronizer(c *cache.Cache) Synchronizer {
	return Synchronizer{
		org:     c.GetORG(),
		cache:   c,
		counter: &counter{},
	}
}

func (s *Synchronizer) assembleMetricLabelFully() ([]*trident.MetricLabelResponse, error) {
	nonLabelNames := mapset.NewSet[string]()
	metricNameToAPPLabelNames := make(map[string][]*trident.LabelResponse, 0)
	for k, v := range s.cache.MetricAndAPPLabelLayout.GetLayoutKeyToIndex() {
		labelNameID, ok := s.cache.LabelName.GetIDByName(k.LabelName)
		if !ok {
			nonLabelNames.Add(k.LabelName)
			continue
		}
		metricNameToAPPLabelNames[k.MetricName] = append(
			metricNameToAPPLabelNames[k.MetricName],
			&trident.LabelResponse{
				Name:                &k.LabelName,
				NameId:              proto.Uint32(uint32(labelNameID)),
				AppLabelColumnIndex: proto.Uint32(uint32(v)),
			})
	}

	mLabels := make([]*trident.MetricLabelResponse, 0)
	for k, v := range s.cache.MetricName.GetNameToID() {
		metricName := k
		metricID := v
		mLabels = append(
			mLabels,
			&trident.MetricLabelResponse{
				OrgId:      proto.Uint32(uint32(s.org.GetID())),
				MetricName: &metricName,
				MetricId:   proto.Uint32(uint32((metricID))),
				LabelIds:   metricNameToAPPLabelNames[metricName],
			})
		s.counter.SendMetricCount++
	}
	if nonLabelNames.Cardinality() > 0 {
		log.Warningf("ids of label names not found, %s", logNotFoundDetail(nonLabelNames.ToSlice()))
	}
	return mLabels, nil
}

func (s *Synchronizer) assembleLabelFully() ([]*trident.LabelResponse, error) {
	ls := make([]*trident.LabelResponse, 0)
	nonNameIDs := mapset.NewSet[int]()
	nonValueIDs := mapset.NewSet[int]()
	for k := range s.cache.Label.GetKeyToID() {
		name, okN := s.cache.LabelName.GetNameByID(k.NameID)
		if !okN {
			nonNameIDs.Add(k.NameID)
			continue
		}
		value, okV := s.cache.LabelValue.GetValueByID(k.ValueID)
		if !okV {
			nonValueIDs.Add(k.ValueID)
			continue
		}
		n, v := name, value
		ls = append(ls, &trident.LabelResponse{
			Name:    &n,
			Value:   &v,
			NameId:  proto.Uint32(uint32(k.NameID)),
			ValueId: proto.Uint32(uint32(k.ValueID)),
		})
		s.counter.SendLabelCount++
	}
	if nonNameIDs.Cardinality() > 0 {
		log.Warningf("strings for label name ids not found, %s", logNotFoundDetail(nonNameIDs.ToSlice()))
	}
	if nonValueIDs.Cardinality() > 0 {
		log.Warningf("strings for label value ids not found, %s", logNotFoundDetail(nonValueIDs.ToSlice()))
	}
	return ls, nil
}

// func (s *Synchronizer) assembleTargetFully() ([]*trident.TargetResponse, error) {
// 	var err error
// 	nonInstances := mapset.NewSet[string]()
// 	nonJobs := mapset.NewSet[string]()
// 	targets := make([]*trident.TargetResponse, 0)
// 	for tk, targetID := range s.cache.Target.Get() {
// 		targetKey := tk
// 		tInstanceID, ok := s.cache.LabelValue.GetIDByValue(targetKey.Instance)
// 		if !ok {
// 			nonInstances.Add(targetKey.Instance)
// 			continue
// 		}
// 		tJobID, ok := s.cache.LabelValue.GetIDByValue(targetKey.Job)
// 		if !ok {
// 			nonJobs.Add(targetKey.Job)
// 			continue
// 		}

// 		var labelNIDs []uint32
// 		for _, n := range s.cache.Target.GetLabelNamesByID(targetID) {
// 			if id, ok := s.cache.LabelName.GetIDByName(n); ok {
// 				labelNIDs = append(labelNIDs, uint32(id))
// 			}
// 		}
// 		sort.Slice(labelNIDs, func(i, j int) bool {
// 			return labelNIDs[i] < labelNIDs[j]
// 		})

// 		metricIDs := s.cache.MetricTarget.GetMetricIDsByTargetID(targetID)
// 		sort.Slice(metricIDs, func(i, j int) bool {
// 			return metricIDs[i] < metricIDs[j]
// 		})

// 		targets = append(targets, &trident.TargetResponse{
// 			OrgId:              proto.Uint32(uint32(s.org.GetID())),
// 			Instance:           &targetKey.Instance,
// 			Job:                &targetKey.Job,
// 			InstanceId:         proto.Uint32(uint32(tInstanceID)),
// 			JobId:              proto.Uint32(uint32(tJobID)),
// 			TargetId:           proto.Uint32(uint32(targetID)),
// 			MetricIds:          metricIDs,
// 			TargetLabelNameIds: labelNIDs,
// 			PodClusterId:       proto.Uint32(uint32(targetKey.PodClusterID)),
// 			EpcId:              proto.Uint32(uint32(targetKey.VPCID)),
// 		})
// 		s.counter.SendTargetCount++
// 	}

// 	sort.Slice(targets, func(i, j int) bool {
// 		return targets[i].GetTargetId() < targets[j].GetTargetId()
// 	})

// 	if nonInstances.Cardinality() > 0 {
// 		log.Warningf("target instance id not found, instances: %v", nonInstances.ToSlice()))
// 	}
// 	if nonJobs.Cardinality() > 0 {
// 		log.Warningf("target job id not found, jobs: %v", nonJobs.ToSlice()))
// 	}
// 	return targets, err
// }
