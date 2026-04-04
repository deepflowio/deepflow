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

	mapset "github.com/deckarep/golang-set/v2"
	"google.golang.org/protobuf/proto"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("prometheus.synchronizer")

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
	var err error
	nonLabelNames := mapset.NewSet[string]()
	metricNameToAPPLabelNames := make(map[string][]*trident.LabelResponse, 0)
	for key, index := range s.cache.MetricAndAPPLabelLayout.GetLayoutKeyToIndex() {
		labelNameID, ok := s.cache.LabelName.GetIDByName(key.LabelName)
		if !ok {
			nonLabelNames.Add(key.LabelName)
			continue
		}
		labelName := key.LabelName
		metricNameToAPPLabelNames[key.MetricName] = append(
			metricNameToAPPLabelNames[key.MetricName],
			&trident.LabelResponse{
				Name:                &labelName,
				NameId:              proto.Uint32(uint32(labelNameID)),
				AppLabelColumnIndex: proto.Uint32(uint32(index)),
			})
	}

	mLabels := make([]*trident.MetricLabelResponse, 0)
	for metricName, metricID := range s.cache.MetricName.GetNameToID() {
		mn := metricName
		mLabels = append(
			mLabels,
			&trident.MetricLabelResponse{
				OrgId:      proto.Uint32(uint32(s.org.GetID())),
				MetricName: &mn,
				MetricId:   proto.Uint32(uint32((metricID))),
				LabelIds:   metricNameToAPPLabelNames[mn],
			})
		s.counter.SendMetricCount++
	}
	if nonLabelNames.Cardinality() > 0 {
		log.Warningf("label name id not found, names: %v", nonLabelNames.ToSlice(), s.org.LogPrefix)
	}
	return mLabels, err
}

func (s *Synchronizer) assembleLabelFully() ([]*trident.LabelResponse, error) {
	ls := make([]*trident.LabelResponse, 0)
	nonLabelNames := mapset.NewSet[string]()
	nonLabelValues := mapset.NewSet[string]()
	for k, _ := range s.cache.Label.GetKeyToID() {
		ni, ok := s.cache.LabelName.GetIDByName(k.Name)
		if !ok {
			nonLabelNames.Add(k.Name)
			continue
		}
		vi, ok := s.cache.LabelValue.GetIDByValue(k.Value)
		if !ok {
			nonLabelValues.Add(k.Value)
			continue
		}
		name := k.Name
		value := k.Value
		ls = append(ls, &trident.LabelResponse{
			Name:    &name,
			Value:   &value,
			NameId:  proto.Uint32(uint32(ni)),
			ValueId: proto.Uint32(uint32(vi)),
		})
		s.counter.SendLabelCount++
	}
	if nonLabelNames.Cardinality() > 0 {
		log.Warningf("label name id not found, names: %v", nonLabelNames.ToSlice(), s.org.LogPrefix)
	}
	if nonLabelValues.Cardinality() > 0 {
		log.Warningf("label value id not found, values: %v", nonLabelValues.ToSlice(), s.org.LogPrefix)
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
