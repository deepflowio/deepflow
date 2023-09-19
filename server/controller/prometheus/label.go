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
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/grpc/statsd"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
	. "github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

type LabelSynchronizer struct {
	Synchronizer
	grpcurl       *GRPCURL
	statsdCounter *statsd.PrometheusLabelIDsCounter
}

func NewLabelSynchronizer() *LabelSynchronizer {
	return &LabelSynchronizer{
		Synchronizer: Synchronizer{
			cache:   cache.GetSingleton(),
			counter: &counter{},
		},
		grpcurl:       new(GRPCURL),
		statsdCounter: statsd.NewPrometheusLabelIDsCounter(),
	}
}

func (s *LabelSynchronizer) Sync(req *trident.PrometheusLabelRequest) (*trident.PrometheusLabelResponse, error) {
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

func (s *LabelSynchronizer) GetStatsdCounter() *statsd.PrometheusLabelIDsCounter {
	return s.statsdCounter
}

func (s *LabelSynchronizer) assembleFully() (*trident.PrometheusLabelResponse, error) {
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
	s.setStatsdCounter()
	return resp, err
}

func (s *LabelSynchronizer) setStatsdCounter() {
	s.statsdCounter.SendMetricCount = s.counter.SendMetricCount
	s.statsdCounter.SendLabelCount = s.counter.SendLabelCount
	s.statsdCounter.SendTargetCount = s.counter.SendTargetCount
}

func (s *LabelSynchronizer) prepare(req *trident.PrometheusLabelRequest) error {
	toEncode := s.generateDataToEncode(req)
	if toEncode.cardinality() == 0 {
		return nil
	}

	syncResp, err := s.grpcurl.Sync(s.generateSyncRequest(toEncode))
	if err != nil {
		return errors.Wrap(err, "grpcurl.Sync")
	}
	eg := &errgroup.Group{}
	AppendErrGroup(eg, s.addMetricNameCache, syncResp.GetMetricNames())
	AppendErrGroup(eg, s.addLabelNameCache, syncResp.GetLabelNames())
	AppendErrGroup(eg, s.addLabelValueCache, syncResp.GetLabelValues())
	AppendErrGroup(eg, s.addMetricAPPLabelLayoutCache, syncResp.GetMetricAppLabelLayouts())
	AppendErrGroup(eg, s.addLabelCache, syncResp.GetLabels())
	AppendErrGroup(eg, s.addMetricLabelCache, toEncode.metricToMetricLabels)
	AppendErrGroup(eg, s.addMetricTargetCache, syncResp.GetMetricTargets())
	AppendErrGroup(eg, s.addTargetCache, syncResp.GetTargets())
	return eg.Wait()
}

func (s *LabelSynchronizer) generateDataToEncode(req *trident.PrometheusLabelRequest) *dataToEncode {
	toEncode := newDataToEncode()
	for _, m := range req.GetRequestLabels() {
		mn := m.GetMetricName()
		toEncode.tryAppendMetricName(mn)
		targetKey, targetID, targetExists := s.getTargetInfoFromLabels(m)
		if targetExists {
			toEncode.tryAppendMetricTarget(mn, targetID)
		} else {
			toEncode.appendMetricTarget(mn, targetKey)
		}

		for _, l := range m.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			toEncode.tryAppendLabelName(ln)
			toEncode.tryAppendLabelValue(lv)
			toEncode.tryAppendLabel(ln, lv)
			toEncode.tryAppendMetricLabel(mn, ln, lv)
			if ln == TargetLabelInstance || ln == TargetLabelJob {
				continue
			}
			if targetExists {
				toEncode.tryAppendMetricAPPLabelLayout(mn, ln)
			} else {
				toEncode.appendMetricAPPLabelLayout(mn, ln)
			}
		}
	}

	for _, t := range req.GetRequestTargets() {
		toEncode.tryAppendTarget(t.GetInstance(), t.GetJob(), int(t.GetPodClusterId()))
	}
	return toEncode
}

func (s *LabelSynchronizer) generateSyncRequest(toEncode *dataToEncode) *controller.SyncPrometheusRequest {
	return &controller.SyncPrometheusRequest{
		MetricNames: toEncode.metricNames.ToSlice(),
		LabelNames:  toEncode.labelNames.ToSlice(),
		LabelValues: toEncode.labelValues.ToSlice(),

		MetricAppLabelLayouts: func(ks []cache.LayoutKey) []*controller.PrometheusMetricAPPLabelLayoutRequest {
			res := make([]*controller.PrometheusMetricAPPLabelLayoutRequest, 0, len(ks))
			for i := range ks {
				res = append(res, &controller.PrometheusMetricAPPLabelLayoutRequest{
					MetricName:   &ks[i].MetricName,
					AppLabelName: &ks[i].LabelName,
				})
			}
			return res
		}(toEncode.metricAPPLabelLayouts.ToSlice()),

		Labels: func(ks []cache.LabelKey) []*controller.PrometheusLabelRequest {
			res := make([]*controller.PrometheusLabelRequest, 0, len(ks))
			for i := range ks {
				res = append(res, &controller.PrometheusLabelRequest{
					Name:  &ks[i].Name,
					Value: &ks[i].Value,
				})
			}
			return res
		}(toEncode.labels.ToSlice()),

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
		}(toEncode.metricToMetricLabels),

		MetricTargets: func(ks []cache.MetricTargetKey, iks map[string]mapset.Set[cache.TargetKey]) []*controller.PrometheusMetricTargetRequest {
			res := make([]*controller.PrometheusMetricTargetRequest, 0, len(ks))
			for i := range ks {
				res = append(res, &controller.PrometheusMetricTargetRequest{
					MetricName: &ks[i].MetricName,
					TargetId:   proto.Uint32(uint32(ks[i].TargetID)),
				})
			}
			for k, v := range iks {
				mn := k
				ts := v.ToSlice()
				for i := range ts {
					res = append(res, &controller.PrometheusMetricTargetRequest{
						MetricName:   &mn,
						Instance:     &ts[i].Instance,
						Job:          &ts[i].Job,
						PodClusterId: proto.Uint32(uint32(ts[i].PodClusterID)),
					})
				}
			}
			return res
		}(toEncode.metricTargets.ToSlice(), toEncode.metricToTargets),

		Targets: func(ts []cache.TargetKey) []*controller.PrometheusTargetRequest {
			res := make([]*controller.PrometheusTargetRequest, 0, len(ts))
			for i := range ts {
				res = append(res, &controller.PrometheusTargetRequest{
					Instance:     &ts[i].Instance,
					Job:          &ts[i].Job,
					PodClusterId: proto.Uint32(uint32(ts[i].PodClusterID)),
				})
			}
			return res
		}(toEncode.targets.ToSlice()),
	}
}

func (s *LabelSynchronizer) getTargetInfoFromLabels(m *trident.MetricLabelRequest) (cache.TargetKey, int, bool) {
	var instanceValue string
	var insGot bool
	var jobValue string
	var jobGot bool
	for _, l := range m.GetLabels() {
		ln := l.GetName()
		if ln == TargetLabelInstance {
			instanceValue = l.GetValue()
			insGot = true
		} else if ln == TargetLabelJob {
			jobValue = l.GetValue()
			jobGot = true
		}
		if insGot && jobGot {
			break
		}
	}
	targetKey := cache.NewTargetKey(instanceValue, jobValue, int(m.GetPodClusterId()))
	targetID, ok := s.cache.Target.GetIDByKey(targetKey)
	return targetKey, targetID, ok
}

func (s *LabelSynchronizer) assemble(req *trident.PrometheusLabelRequest) (*trident.PrometheusLabelResponse, error) {
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

func (s *LabelSynchronizer) assembleMetricLabel(mls []*trident.MetricLabelRequest) ([]*trident.MetricLabelResponse, error) {
	respMLs := make([]*trident.MetricLabelResponse, 0)

	nonMetricNameToCount := make(map[string]int, 0) // used to count how many times a nonexistent metric name appears, avoid swiping log
	nonLabelNames := mapset.NewSet[string]()
	nonLabelValues := mapset.NewSet[string]()
	for _, ml := range mls {
		s.statsdCounter.ReceiveMetricCount++
		s.statsdCounter.ReceiveLabelCount += uint64(len(ml.GetLabels()))

		var rls []*trident.LabelResponse
		_, _, ok := s.getTargetInfoFromLabels(ml)
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
				MetricName:   &mn,
				MetricId:     proto.Uint32(uint32(mni)),
				LabelIds:     rls,
				PodClusterId: proto.Uint32(uint32(ml.GetPodClusterId())),
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

func (s *LabelSynchronizer) assembleTarget(ts []*trident.TargetRequest) ([]*trident.TargetResponse, error) {
	respTs := make([]*trident.TargetResponse, 0)
	nonTargetKeys := mapset.NewSet[cache.TargetKey]()
	nonInstances := mapset.NewSet[string]()
	nonJobs := mapset.NewSet[string]()
	for _, t := range ts {
		s.statsdCounter.ReceiveTargetCount++
		instance := t.GetInstance()
		job := t.GetJob()
		podClusterID := int(t.GetPodClusterId())
		tID, ok := s.cache.Target.GetIDByKey(cache.NewTargetKey(instance, job, podClusterID))
		if !ok {
			nonTargetKeys.Add(cache.NewTargetKey(instance, job, podClusterID))
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
			Instance:     &instance,
			InstanceId:   proto.Uint32(uint32(insID)),
			Job:          &job,
			JobId:        proto.Uint32(uint32(jobID)),
			TargetId:     proto.Uint32(uint32(tID)),
			PodClusterId: proto.Uint32(uint32(podClusterID)),
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

func (s *LabelSynchronizer) addMetricNameCache(arg ...interface{}) error {
	mns := arg[0].([]*controller.PrometheusMetricName)
	s.cache.MetricName.Add(mns)
	return nil
}

func (s *LabelSynchronizer) addLabelNameCache(arg ...interface{}) error {
	lns := arg[0].([]*controller.PrometheusLabelName)
	s.cache.LabelName.Add(lns)
	return nil
}

func (s *LabelSynchronizer) addLabelValueCache(arg ...interface{}) error {
	lvs := arg[0].([]*controller.PrometheusLabelValue)
	s.cache.LabelValue.Add(lvs)
	return nil
}

func (s *LabelSynchronizer) addMetricAPPLabelLayoutCache(arg ...interface{}) error {
	ls := arg[0].([]*controller.PrometheusMetricAPPLabelLayout)
	s.cache.MetricAndAPPLabelLayout.Add(ls)
	return nil
}

func (s *LabelSynchronizer) addLabelCache(arg ...interface{}) error {
	ls := arg[0].([]*controller.PrometheusLabel)
	s.cache.Label.Add(ls)
	return nil
}

func (s *LabelSynchronizer) addMetricLabelCache(arg ...interface{}) error {
	m := arg[0].(map[string]mapset.Set[cache.MetricLabelDetailKey])
	for _, ks := range m {
		s.cache.MetricLabel.Add(ks.ToSlice())
	}
	return nil
}

func (s *LabelSynchronizer) addMetricTargetCache(arg ...interface{}) error {
	mts := arg[0].([]*controller.PrometheusMetricTarget)
	s.cache.MetricTarget.Add(mts)
	return nil
}

func (s *LabelSynchronizer) addTargetCache(arg ...interface{}) error {
	ts := arg[0].([]*controller.PrometheusTarget)
	s.cache.Target.Add(ts)
	return nil
}

type dataToEncode struct {
	cache *cache.Cache

	metricNames           mapset.Set[string]
	labelNames            mapset.Set[string]
	labelValues           mapset.Set[string]
	metricAPPLabelLayouts mapset.Set[cache.LayoutKey]
	labels                mapset.Set[cache.LabelKey]
	metricToMetricLabels  map[string]mapset.Set[cache.MetricLabelDetailKey]
	metricTargets         mapset.Set[cache.MetricTargetKey]
	metricToTargets       map[string]mapset.Set[cache.TargetKey]
	targets               mapset.Set[cache.TargetKey]
}

func newDataToEncode() *dataToEncode {
	return &dataToEncode{
		cache: cache.GetSingleton(),

		metricNames:           mapset.NewSet[string](),
		labelNames:            mapset.NewSet[string](),
		labelValues:           mapset.NewSet[string](),
		metricAPPLabelLayouts: mapset.NewSet[cache.LayoutKey](),
		labels:                mapset.NewSet[cache.LabelKey](),
		metricToMetricLabels:  make(map[string]mapset.Set[cache.MetricLabelDetailKey], 0),
		metricTargets:         mapset.NewSet[cache.MetricTargetKey](),
		metricToTargets:       make(map[string]mapset.Set[cache.TargetKey], 0),
		targets:               mapset.NewSet[cache.TargetKey](),
	}
}

func (d *dataToEncode) cardinality() int {
	return d.metricNames.Cardinality() + d.labelNames.Cardinality() + d.labelValues.Cardinality() +
		d.metricAPPLabelLayouts.Cardinality() + d.labels.Cardinality() + len(d.metricToMetricLabels) +
		d.metricTargets.Cardinality() + len(d.metricToTargets) + d.targets.Cardinality()
}

func (d *dataToEncode) tryAppendMetricName(name string) {
	if _, ok := d.cache.MetricName.GetIDByName(name); !ok {
		d.metricNames.Add(name)
	}
}

func (d *dataToEncode) tryAppendLabelName(name string) {
	if _, ok := d.cache.LabelName.GetIDByName(name); !ok {
		d.labelNames.Add(name)
	}
}

func (d *dataToEncode) tryAppendLabelValue(value string) {
	if _, ok := d.cache.LabelValue.GetIDByValue(value); !ok {
		d.labelValues.Add(value)
	}
}

func (d *dataToEncode) tryAppendMetricAPPLabelLayout(metricName, labelName string) {
	if ok := d.cache.MetricTarget.IfLabelIsTargetType(metricName, labelName); ok {
		return
	}
	k := cache.NewLayoutKey(metricName, labelName)
	if _, ok := d.cache.MetricAndAPPLabelLayout.GetIndexByKey(k); !ok {
		d.metricAPPLabelLayouts.Add(k)
	}
}

func (d *dataToEncode) appendMetricAPPLabelLayout(metricName, labelName string) {
	d.metricAPPLabelLayouts.Add(cache.NewLayoutKey(metricName, labelName))
}

func (d *dataToEncode) tryAppendLabel(name, value string) {
	if ok := d.cache.Label.IfKeyExists(cache.NewLabelKey(name, value)); !ok {
		d.labels.Add(cache.NewLabelKey(name, value))
	}
}

func (d *dataToEncode) tryAppendMetricLabel(metricName, labelName, labelValue string) {
	mlk := cache.NewMetricLabelDetailKey(metricName, labelName, labelValue)
	if ok := d.cache.MetricLabel.IfKeyExists(mlk); !ok {
		if _, ok := d.metricToMetricLabels[metricName]; !ok {
			d.metricToMetricLabels[metricName] = mapset.NewSet[cache.MetricLabelDetailKey]()
		}
		d.metricToMetricLabels[metricName].Add(mlk)
	}
}

func (d *dataToEncode) tryAppendMetricTarget(metricName string, targetID int) {
	mtk := cache.NewMetricTargetKey(metricName, targetID)
	if ok := d.cache.MetricTarget.IfKeyExists(mtk); !ok {
		d.metricTargets.Add(mtk)
	}
}

func (d *dataToEncode) appendMetricTarget(metricName string, tk cache.TargetKey) {
	if _, ok := d.metricToTargets[metricName]; !ok {
		d.metricToTargets[metricName] = mapset.NewSet[cache.TargetKey]()
	}
	d.metricToTargets[metricName].Add(tk)
}

func (d *dataToEncode) tryAppendTarget(ins, job string, podClusterID int) {
	tk := cache.NewTargetKey(ins, job, podClusterID)
	if _, ok := d.cache.Target.GetIDByKey(tk); !ok {
		d.targets.Add(tk)
	}
}
