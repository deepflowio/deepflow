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
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/golang/protobuf/proto"
	"github.com/op/go-logging"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/grpc/statsd"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
	. "github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

var log = logging.MustGetLogger("prometheus.synchronizer")

type Synchronizer struct {
	cache         *cache.Cache
	grpcurl       *GRPCURL
	statsdCounter *statsd.PrometheusLabelIDsCounter
}

func NewSynchronizer() *Synchronizer {
	return &Synchronizer{
		cache:         cache.GetSingleton(),
		grpcurl:       new(GRPCURL),
		statsdCounter: statsd.NewPrometheusLabelIDsCounter(),
	}
}

func (s *Synchronizer) Sync(req *trident.PrometheusLabelRequest) (*trident.PrometheusLabelResponse, error) {
	if req == nil || (len(req.GetRequestLabels()) == 0 && len(req.GetRequestTargets()) == 0) {
		return s.assembleFully()
	}
	err := s.prepare(req)
	if err != nil {
		log.Errorf("prepare error: %+v", err)
		return nil, err
	}
	return s.assemble(req)
}

func (s *Synchronizer) GetStatsdCounter() *statsd.PrometheusLabelIDsCounter {
	return s.statsdCounter
}

func (s *Synchronizer) assembleFully() (*trident.PrometheusLabelResponse, error) {
	resp := new(trident.PrometheusLabelResponse)
	mls, err := s.assembleMetricLabelFully()
	if err != nil {
		return nil, errors.Wrap(err, "assembleLabelFully")
	}
	resp.ResponseLabelIds = mls
	ts, err := s.assembleTargetFully()
	if err != nil {
		return nil, errors.Wrap(err, "assembleTargetFully")
	}
	resp.ResponseTargetIds = ts
	return resp, err
}

func (s *Synchronizer) assembleMetricLabelFully() ([]*trident.MetricLabelResponse, error) {
	var err error
	nonLabelNames := mapset.NewSet[string]()
	nonLabelValues := mapset.NewSet[string]()
	mLabels := make([]*trident.MetricLabelResponse, 0)
	s.cache.MetricName.Get().Range(func(k, v interface{}) bool {
		var labels []*trident.LabelResponse
		metricName := k.(string)
		metricID := v.(int)
		labelKeys := s.cache.MetricLabel.GetLabelsByMetricName(metricName)
		for i := range labelKeys {
			lk := labelKeys[i]
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
			s.statsdCounter.SendLabelCount++
		}
		mLabels = append(mLabels, &trident.MetricLabelResponse{
			MetricName: &metricName,
			MetricId:   proto.Uint32(uint32((metricID))),
			LabelIds:   labels,
		})
		s.statsdCounter.SendMetricCount++
		return true
	})
	if nonLabelNames.Cardinality() > 0 {
		log.Warningf("label name id not found, names: %v", nonLabelNames.ToSlice())
	}
	if nonLabelValues.Cardinality() > 0 {
		log.Warningf("label value id not found, values: %v", nonLabelValues.ToSlice())
	}
	return mLabels, err
}

func (s *Synchronizer) assembleTargetFully() ([]*trident.TargetResponse, error) {
	var err error
	nonInstances := mapset.NewSet[string]()
	nonJobs := mapset.NewSet[string]()
	targets := make([]*trident.TargetResponse, 0)
	for tk, targetID := range s.cache.Target.Get() {
		tInstanceID, ok := s.cache.LabelValue.GetIDByValue(tk.Instance)
		if !ok {
			nonInstances.Add(tk.Instance)
			continue
		}
		tJobID, ok := s.cache.LabelValue.GetIDByValue(tk.Job)
		if !ok {
			nonJobs.Add(tk.Job)
			continue
		}
		targets = append(targets, &trident.TargetResponse{
			Instance:   &tk.Instance,
			Job:        &tk.Job,
			InstanceId: proto.Uint32(uint32(tInstanceID)),
			JobId:      proto.Uint32(uint32(tJobID)),
			TargetId:   proto.Uint32(uint32(targetID)),
			MetricIds:  s.cache.MetricTarget.GetMetricIDsByTargetID(targetID),
		})
		s.statsdCounter.SendTargetCount++
	}
	if nonInstances.Cardinality() > 0 {
		log.Warningf("target instance id not found, instances: %v", nonInstances.ToSlice())
	}
	if nonJobs.Cardinality() > 0 {
		log.Warningf("target job id not found, jobs: %v", nonJobs.ToSlice())
	}
	return targets, err
}

func (s *Synchronizer) prepare(req *trident.PrometheusLabelRequest) error {
	metricNamesToE := mapset.NewSet[string]()
	labelNamesToE := mapset.NewSet[string]()
	labelValuesToE := mapset.NewSet[string]()
	metricAPPLabelLayoutsToE := mapset.NewSet[cache.LayoutKey]()
	labelsToAdd := mapset.NewSet[cache.LabelKey]()
	metricLabelsToAdd := make(map[string]mapset.Set[cache.MetricLabelDetailKey], 0)
	metricTargetsToAdd := mapset.NewSet[cache.MetricTargetKey]()

	nonTargetKeyToCount := make(map[cache.TargetKey]int, 0) // used to count how many times a nonexistent target key appears, avoid swiping log
	for _, m := range req.GetRequestLabels() {
		mn := m.GetMetricName()
		if mn == "" {
			continue
		}
		targetKey, targetID, ok := s.getTargetInfoFromLabels(m.GetLabels())
		if ok {
			s.tryAppendMetricNameToEncode(metricNamesToE, mn)
			s.tryAppendMetricTargetToAdd(metricTargetsToAdd, mn, targetID)
			for _, l := range m.GetLabels() {
				ln := l.GetName()
				if ln == "" {
					continue
				}
				lv := l.GetValue()
				s.tryAppendLabelNameToEncode(labelNamesToE, ln)
				s.tryAppendLabelValueToEncode(labelValuesToE, lv)
				s.tryAppendLabelToAdd(labelsToAdd, ln, lv)
				s.tryAppendMetricLabelToAdd(metricLabelsToAdd, mn, ln, lv)
				if ln == TargetLabelInstance || ln == TargetLabelJob {
					continue
				}
				s.tryAppendMetricAPPLabelLayoutToEncode(metricAPPLabelLayoutsToE, mn, ln, targetID)
			}
		} else {
			nonTargetKeyToCount[targetKey]++
		}
	}

	if len(nonTargetKeyToCount) != 0 {
		log.Warningf("target id not found, target key to request count: %+v", nonTargetKeyToCount)
	}

	if metricNamesToE.Cardinality() == 0 && labelNamesToE.Cardinality() == 0 && labelValuesToE.Cardinality() == 0 &&
		metricAPPLabelLayoutsToE.Cardinality() == 0 && labelsToAdd.Cardinality() == 0 && len(metricLabelsToAdd) == 0 &&
		metricTargetsToAdd.Cardinality() == 0 {
		return nil
	}

	syncResp, err := s.grpcurl.Sync(
		&controller.SyncPrometheusRequest{
			MetricNames: metricNamesToE.ToSlice(),
			LabelNames:  labelNamesToE.ToSlice(),
			LabelValues: labelValuesToE.ToSlice(),
			MetricAppLabelLayouts: func(ks []cache.LayoutKey) []*controller.PrometheusMetricAPPLabelLayoutRequest {
				res := make([]*controller.PrometheusMetricAPPLabelLayoutRequest, 0, len(ks))
				for i := range ks {
					res = append(res, &controller.PrometheusMetricAPPLabelLayoutRequest{
						MetricName:   &ks[i].MetricName,
						AppLabelName: &ks[i].LabelName,
					})
				}
				return res
			}(metricAPPLabelLayoutsToE.ToSlice()),
			Labels: func(ks []cache.LabelKey) []*controller.PrometheusLabelRequest {
				res := make([]*controller.PrometheusLabelRequest, 0, len(ks))
				for i := range ks {
					res = append(res, &controller.PrometheusLabelRequest{
						Name:  &ks[i].Name,
						Value: &ks[i].Value,
					})
				}
				return res
			}(labelsToAdd.ToSlice()),
			MetricLabels: func(m map[string]mapset.Set[cache.MetricLabelDetailKey]) []*controller.PrometheusMetricLabelRequest {
				res := make([]*controller.PrometheusMetricLabelRequest, 0, len(m))
				for mn, lks := range m {
					rmn := mn
					var ls []*controller.PrometheusLabelRequest
					lkl := lks.ToSlice()
					for i := range lkl {
						ls = append(ls, &controller.PrometheusLabelRequest{
							Name:  &lkl[i].LabelName,
							Value: &lkl[i].LabelValue,
						})
					}
					res = append(res, &controller.PrometheusMetricLabelRequest{
						MetricName: &rmn,
						Labels:     ls,
					})
				}
				return res
			}(metricLabelsToAdd),
			MetricTargets: func(ks []cache.MetricTargetKey) []*controller.PrometheusMetricTarget {
				res := make([]*controller.PrometheusMetricTarget, 0, len(ks))
				for i := range ks {
					res = append(res, &controller.PrometheusMetricTarget{
						MetricName: &ks[i].MetricName,
						TargetId:   proto.Uint32(uint32(ks[i].TargetID)),
					})
				}
				return res
			}(metricTargetsToAdd.ToSlice()),
		},
	)
	if err != nil {
		return errors.Wrap(err, "grpcurl.Sync")
	}
	eg := &errgroup.Group{}
	AppendErrGroup(eg, s.addMetricNameCache, syncResp.GetMetricNames())
	AppendErrGroup(eg, s.addLabelNameCache, syncResp.GetLabelNames())
	AppendErrGroup(eg, s.addLabelValueCache, syncResp.GetLabelValues())
	AppendErrGroup(eg, s.addMetricAPPLabelLayoutCache, syncResp.GetMetricAppLabelLayouts())
	AppendErrGroup(eg, s.addLabelCache, syncResp.GetLabels())
	AppendErrGroup(eg, s.addMetricLabelCache, metricLabelsToAdd)
	AppendErrGroup(eg, s.addMetricTargetCache, metricTargetsToAdd)
	return eg.Wait()
}

func (s *Synchronizer) getTargetInfoFromLabels(labels []*trident.LabelRequest) (cache.TargetKey, int, bool) {
	var instanceValue string
	var jobValue string
	for _, l := range labels {
		ln := l.GetName()
		if ln == TargetLabelInstance {
			instanceValue = l.GetValue()
		} else if ln == TargetLabelJob {
			jobValue = l.GetValue()
		}
		if instanceValue != "" && jobValue != "" {
			break
		}
	}
	targetKey := cache.NewTargetKey(instanceValue, jobValue)
	targetID, ok := s.cache.Target.GetIDByKey(targetKey)
	return targetKey, targetID, ok
}

func (s *Synchronizer) assemble(req *trident.PrometheusLabelRequest) (*trident.PrometheusLabelResponse, error) {
	resp := new(trident.PrometheusLabelResponse)
	mls, err := s.assembleMetricLabel(req.GetRequestLabels())
	if err != nil {
		return nil, errors.Wrap(err, "assembleMetricLabel")
	}
	resp.ResponseLabelIds = mls
	ts, err := s.assembleTarget(req.GetRequestTargets())
	if err != nil {
		return nil, errors.Wrap(err, "assembleTarget")
	}
	resp.ResponseTargetIds = ts
	return resp, nil
}

func (s *Synchronizer) assembleMetricLabel(mls []*trident.MetricLabelRequest) ([]*trident.MetricLabelResponse, error) {
	respMLs := make([]*trident.MetricLabelResponse, 0)

	nonMetricNameToCount := make(map[string]int, 0) // used to count how many times a nonexistent metric name appears, avoid swiping log
	nonLabelNames := mapset.NewSet[string]()
	nonLabelValues := mapset.NewSet[string]()
	for _, ml := range mls {
		s.statsdCounter.ReceiveMetricCount++
		s.statsdCounter.ReceiveLabelCount += uint64(len(ml.GetLabels()))

		var rls []*trident.LabelResponse
		_, _, ok := s.getTargetInfoFromLabels(ml.GetLabels())
		// responses column index only if instance and job matches one target
		if ok {
			mn := ml.GetMetricName()
			mni, ok := s.cache.MetricName.GetIDByName(mn)
			if !ok {
				nonMetricNameToCount[mn]++
				continue
			}

			for _, l := range ml.GetLabels() {
				ln := l.GetName()
				lv := l.GetValue()
				ni, ok := s.cache.LabelName.GetIDByName(ln)
				if !ok {
					nonLabelNames.Add(ln)
					continue
				}
				vi, ok := s.cache.LabelValue.GetIDByValue(lv)
				if !ok {
					nonLabelValues.Add(lv)
					continue
				}
				id, _ := s.cache.MetricAndAPPLabelLayout.GetIndexByKey(cache.NewLayoutKey(mn, ln))
				rls = append(rls, &trident.LabelResponse{
					Name:                &ln,
					NameId:              proto.Uint32(uint32(ni)),
					Value:               &lv,
					ValueId:             proto.Uint32(uint32(vi)),
					AppLabelColumnIndex: proto.Uint32(uint32(id)),
				})
				s.statsdCounter.SendLabelCount++
			}
			respMLs = append(respMLs, &trident.MetricLabelResponse{
				MetricName: &mn,
				MetricId:   proto.Uint32(uint32(mni)),
				LabelIds:   rls,
			})
			s.statsdCounter.SendMetricCount++
		}
	}
	if len(nonMetricNameToCount) != 0 {
		log.Errorf("metric name id not found, name to request count: %+v", nonMetricNameToCount)
	}
	if nonLabelNames.Cardinality() > 0 {
		log.Errorf("label name id not found, names: %v", nonLabelNames.ToSlice())
	}
	if nonLabelValues.Cardinality() > 0 {
		log.Errorf("label value id not found, values: %v", nonLabelValues.ToSlice())
	}
	return respMLs, nil
}

func (s *Synchronizer) assembleTarget(ts []*trident.TargetRequest) ([]*trident.TargetResponse, error) {
	respTs := make([]*trident.TargetResponse, 0)
	nonTargetKeys := mapset.NewSet[cache.TargetKey]()
	nonInstances := mapset.NewSet[string]()
	nonJobs := mapset.NewSet[string]()
	for _, t := range ts {
		s.statsdCounter.ReceiveTargetCount++
		instance := t.GetInstance()
		job := t.GetJob()
		tID, ok := s.cache.Target.GetIDByKey(cache.NewTargetKey(instance, job))
		if !ok {
			nonTargetKeys.Add(cache.NewTargetKey(instance, job))
			continue
		}
		insID, ok := s.cache.LabelValue.GetIDByValue(instance)
		if !ok {
			nonInstances.Add(instance)
			continue
		}
		jobID, ok := s.cache.LabelValue.GetIDByValue(job)
		if !ok {
			nonJobs.Add(job)
			continue
		}
		respTs = append(respTs, &trident.TargetResponse{
			Instance:   &instance,
			InstanceId: proto.Uint32(uint32(insID)),
			Job:        &job,
			JobId:      proto.Uint32(uint32(jobID)),
			TargetId:   proto.Uint32(uint32(tID)),
		})
		s.statsdCounter.SendTargetCount++
	}
	if nonTargetKeys.Cardinality() > 0 {
		log.Debugf("target id not found, target keys: %+v ", nonTargetKeys.ToSlice())
	}
	if nonInstances.Cardinality() > 0 {
		log.Errorf("target instance id not found, instances: %v", nonInstances.ToSlice())
	}
	if nonJobs.Cardinality() > 0 {
		log.Errorf("target job id not found, jobs: %v", nonJobs.ToSlice())
	}
	return respTs, nil
}

func (s *Synchronizer) tryAppendMetricNameToEncode(toEn mapset.Set[string], name string) {
	if _, ok := s.cache.MetricName.GetIDByName(name); !ok {
		toEn.Add(name)
	}
}

func (s *Synchronizer) addMetricNameCache(arg ...interface{}) error {
	mns := arg[0].([]*controller.PrometheusMetricName)
	s.cache.MetricName.Add(mns)
	return nil
}

func (s *Synchronizer) tryAppendLabelNameToEncode(toEn mapset.Set[string], name string) {
	if _, ok := s.cache.LabelName.GetIDByName(name); !ok {
		toEn.Add(name)
	}
}

func (s *Synchronizer) addLabelNameCache(arg ...interface{}) error {
	lns := arg[0].([]*controller.PrometheusLabelName)
	s.cache.LabelName.Add(lns)
	return nil
}

func (s *Synchronizer) tryAppendLabelValueToEncode(toEn mapset.Set[string], name string) {
	if _, ok := s.cache.LabelValue.GetIDByValue(name); !ok {
		toEn.Add(name)
	}
}

func (s *Synchronizer) addLabelValueCache(arg ...interface{}) error {
	lvs := arg[0].([]*controller.PrometheusLabelValue)
	s.cache.LabelValue.Add(lvs)
	return nil
}

func (s *Synchronizer) tryAppendMetricAPPLabelLayoutToEncode(toEn mapset.Set[cache.LayoutKey], metricName, labelName string, targetID int) {
	if ok := s.cache.Target.IfTargetLabelKeyExists(cache.NewTargetLabelKey(targetID, labelName)); ok {
		return
	}
	k := cache.NewLayoutKey(metricName, labelName)
	if _, ok := s.cache.MetricAndAPPLabelLayout.GetIndexByKey(k); !ok {
		toEn.Add(k)
	}
}

func (s *Synchronizer) addMetricAPPLabelLayoutCache(arg ...interface{}) error {
	ls := arg[0].([]*controller.PrometheusMetricAPPLabelLayout)
	s.cache.MetricAndAPPLabelLayout.Add(ls)
	return nil
}

func (s *Synchronizer) tryAppendLabelToAdd(toAdd mapset.Set[cache.LabelKey], name, value string) {
	if ok := s.cache.Label.IfKeyExists(cache.NewLabelKey(name, value)); !ok {
		toAdd.Add(cache.NewLabelKey(name, value))
	}
}

func (s *Synchronizer) addLabelCache(arg ...interface{}) error {
	ls := arg[0].([]*controller.PrometheusLabel)
	s.cache.Label.Add(ls)
	return nil
}

func (s *Synchronizer) tryAppendMetricLabelToAdd(toAdd map[string]mapset.Set[cache.MetricLabelDetailKey], metricName, labelName, labelValue string) {
	mlk := cache.NewMetricLabelDetailKey(metricName, labelName, labelValue)
	if ok := s.cache.MetricLabel.IfKeyExists(mlk); !ok {
		if _, ok := toAdd[metricName]; !ok {
			toAdd[metricName] = mapset.NewSet[cache.MetricLabelDetailKey]()
		}
		toAdd[metricName].Add(mlk)
	}
}

func (s *Synchronizer) addMetricLabelCache(arg ...interface{}) error {
	m := arg[0].(map[string]mapset.Set[cache.MetricLabelDetailKey])
	for _, ks := range m {
		s.cache.MetricLabel.Add(ks.ToSlice())
	}
	return nil
}

func (s *Synchronizer) tryAppendMetricTargetToAdd(toAdd mapset.Set[cache.MetricTargetKey], metricName string, targetID int) {
	mtk := cache.NewMetricTargetKey(metricName, targetID)
	if ok := s.cache.MetricTarget.IfKeyExists(mtk); !ok {
		toAdd.Add(mtk)
	}
}

func (s *Synchronizer) addMetricTargetCache(arg ...interface{}) error {
	ts := arg[0].(mapset.Set[cache.MetricTargetKey]).ToSlice()
	s.cache.MetricTarget.Add(ts)
	return nil
}
