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

package prometheus

import (
	"sort"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/golang/protobuf/proto"
	"github.com/op/go-logging"
	"golang.org/x/exp/slices"

	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
	. "github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

var log = logging.MustGetLogger("prometheus.synchronizer")

type counter struct {
	SendMetricCount uint64
	SendLabelCount  uint64
	SendTargetCount uint64
}

type Synchronizer struct {
	cache   *cache.Cache
	counter *counter
}

func NewSynchronizer() *Synchronizer {
	return &Synchronizer{
		cache: cache.GetSingleton(),
	}
}

func (s *Synchronizer) assembleMetricLabelFully() ([]*trident.MetricLabelResponse, error) {
	var err error
	nonLabelNames := mapset.NewSet[string]()
	nonLabelValues := mapset.NewSet[string]()
	nonLabelIDs := mapset.NewSet[int]()
	mLabels := make([]*trident.MetricLabelResponse, 0)
	s.cache.MetricName.Get().Range(func(k, v interface{}) bool {
		var labels []*trident.LabelResponse
		metricName := k.(string)
		metricID := v.(int)
		labelIDs := s.cache.MetricLabel.GetLabelsByMetricName(metricName)
		for i := range labelIDs {
			li := labelIDs[i]
			lk, ok := s.cache.Label.GetKeyByID(li)
			if !ok {
				nonLabelIDs.Add(li)
				continue
			}
			if slices.Contains([]string{TargetLabelInstance, TargetLabelJob}, lk.Name) {
				continue
			}
			labelNameID, ok := s.cache.LabelName.GetIDByName(lk.Name)
			if !ok {
				nonLabelNames.Add(lk.Name)
				continue
			}
			labelValueID, ok := s.cache.LabelValue.GetIDByValue(lk.Value)
			if !ok {
				nonLabelValues.Add(lk.Value)
				continue
			}
			idx, _ := s.cache.MetricAndAPPLabelLayout.GetIndexByKey(cache.NewLayoutKey(metricName, lk.Name))
			label := &trident.LabelResponse{
				Name:                &lk.Name,
				Value:               &lk.Value,
				NameId:              proto.Uint32(uint32(labelNameID)),
				ValueId:             proto.Uint32(uint32(labelValueID)),
				AppLabelColumnIndex: proto.Uint32(uint32(idx)),
			}
			labels = append(labels, label)
			s.counter.SendLabelCount++
		}
		mLabels = append(mLabels, &trident.MetricLabelResponse{
			MetricName: &metricName,
			MetricId:   proto.Uint32(uint32((metricID))),
			LabelIds:   labels,
		})
		s.counter.SendMetricCount++
		return true
	})
	if nonLabelNames.Cardinality() > 0 {
		log.Warningf("label name id not found, names: %v", nonLabelNames.ToSlice())
	}
	if nonLabelValues.Cardinality() > 0 {
		log.Warningf("label value id not found, values: %v", nonLabelValues.ToSlice())
	}
	if nonLabelIDs.Cardinality() > 0 {
		log.Warningf("label id not found, ids: %v", nonLabelIDs.ToSlice())
	}
	return mLabels, err
}

func (s *Synchronizer) assembleTargetFully() ([]*trident.TargetResponse, error) {
	var err error
	nonInstances := mapset.NewSet[string]()
	nonJobs := mapset.NewSet[string]()
	targets := make([]*trident.TargetResponse, 0)
	for tk, targetID := range s.cache.Target.Get() {
		targetKey := tk
		tInstanceID, ok := s.cache.LabelValue.GetIDByValue(targetKey.Instance)
		if !ok {
			nonInstances.Add(targetKey.Instance)
			continue
		}
		tJobID, ok := s.cache.LabelValue.GetIDByValue(targetKey.Job)
		if !ok {
			nonJobs.Add(targetKey.Job)
			continue
		}

		var labelNIDs []uint32
		for _, n := range s.cache.Target.GetLabelNamesByID(targetID) {
			if id, ok := s.cache.LabelName.GetIDByName(n); ok {
				labelNIDs = append(labelNIDs, uint32(id))
			}
		}
		sort.Slice(labelNIDs, func(i, j int) bool {
			return labelNIDs[i] < labelNIDs[j]
		})

		metricIDs := s.cache.MetricTarget.GetMetricIDsByTargetID(targetID)
		sort.Slice(metricIDs, func(i, j int) bool {
			return metricIDs[i] < metricIDs[j]
		})

		targets = append(targets, &trident.TargetResponse{
			Instance:           &targetKey.Instance,
			Job:                &targetKey.Job,
			InstanceId:         proto.Uint32(uint32(tInstanceID)),
			JobId:              proto.Uint32(uint32(tJobID)),
			TargetId:           proto.Uint32(uint32(targetID)),
			MetricIds:          metricIDs,
			TargetLabelNameIds: labelNIDs,
			PodClusterId:       proto.Uint32(uint32(targetKey.PodClusterID)),
		})
		s.counter.SendTargetCount++
	}

	sort.Slice(targets, func(i, j int) bool {
		return targets[i].GetTargetId() < targets[j].GetTargetId()
	})

	if nonInstances.Cardinality() > 0 {
		log.Warningf("target instance id not found, instances: %v", nonInstances.ToSlice())
	}
	if nonJobs.Cardinality() > 0 {
		log.Warningf("target job id not found, jobs: %v", nonJobs.ToSlice())
	}
	return targets, err
}
