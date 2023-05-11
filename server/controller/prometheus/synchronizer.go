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
	"context"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/golang/protobuf/proto"
	"github.com/op/go-logging"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
	. "github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

var log = logging.MustGetLogger("prometheus")

type Synchronizer struct {
	cache   *cache.Cache
	grpcurl *GRPCURL
}

func NewSynchronizer() *Synchronizer {
	return &Synchronizer{
		cache:   cache.GetSingleton(),
		grpcurl: new(GRPCURL),
	}
}

func (e *Synchronizer) Sync(req *trident.PrometheusLabelRequest) (*trident.PrometheusLabelResponse, error) {
	if req == nil || (len(req.GetRequestLabels()) == 0 && len(req.GetRequestTargets()) == 0) {
		return e.assembleFully()
	}
	err := e.prepare(req)
	if err != nil {
		log.Errorf("prepare error: %+v", err)
		return nil, err
	}
	return e.assemble(req)
}

func (e *Synchronizer) assembleFully() (*trident.PrometheusLabelResponse, error) {
	defer e.cache.Clear()
	err := e.cache.RefreshFully()
	if err != nil {
		return nil, err
	}
	resp := new(trident.PrometheusLabelResponse)
	mls, err := e.assembleLabelFully()
	if err != nil {
		return nil, errors.Wrap(err, "assembleLabelFully")
	}
	resp.ResponseLabelIds = mls
	ts, err := e.assembleTargetFully()
	if err != nil {
		return nil, errors.Wrap(err, "assembleTargetFully")
	}
	resp.ResponseTargetIds = ts
	return resp, err
}

func (e *Synchronizer) assembleLabelFully() ([]*trident.MetricLabelResponse, error) {
	var err error
	mLabels := make([]*trident.MetricLabelResponse, 0)
	e.cache.MetricName.Get().Range(func(k, v interface{}) bool {
		var labels []*trident.LabelResponse
		metricName := k.(string)
		metricID := v.(int)
		labelKeys := e.cache.MetricLabel.GetLabelsByMetricName(metricName)
		for i := range labelKeys {
			lk := labelKeys[i]
			labelNameID, ok := e.cache.LabelName.GetIDByName(lk.Name)
			if !ok {
				log.Warningf("metric_name: %s label_name: %s id not found", metricName, lk.Name)
				continue
			}
			labelValueID, ok := e.cache.LabelValue.GetIDByValue(lk.Value)
			if !ok {
				log.Warningf("metric_name: %s label_value: %s id not found", metricName, lk.Value)
				continue
			}
			idx, ok := e.cache.MetricAndAPPLabelLayout.GetIndexByKey(cache.NewLayoutKey(metricName, lk.Name))
			if !ok {
				log.Warningf("app_label_index (metric_name: %s, app_label_name: %s) not found", metricName, lk.Name)
				continue
			}
			label := &trident.LabelResponse{
				Name:                &lk.Name,
				Value:               &lk.Value,
				NameId:              proto.Uint32(uint32(labelNameID)),
				ValueId:             proto.Uint32(uint32(labelValueID)),
				AppLabelColumnIndex: proto.Uint32(uint32(idx)),
			}
			labels = append(labels, label)
		}
		mLabels = append(mLabels, &trident.MetricLabelResponse{
			MetricName: &metricName,
			MetricId:   proto.Uint32(uint32((metricID))),
			LabelIds:   labels,
		})
		return true
	})
	return mLabels, err
}

func (e *Synchronizer) assembleTargetFully() ([]*trident.TargetResponse, error) {
	var err error
	targets := make([]*trident.TargetResponse, 0)
	e.cache.Target.Get().Range(func(k, v interface{}) bool {
		tk := k.(cache.TargetKey)
		tInstanceID, ok := e.cache.LabelValue.GetIDByValue(tk.Instance)
		if !ok {
			log.Warningf("target: %s instance id not found", tk.Instance)
			return true
		}
		tJobID, ok := e.cache.LabelValue.GetIDByValue(tk.Job)
		if !ok {
			log.Warningf("target: %s job id not found", tk.Job)
			return true
		}
		targetID := v.(int)
		targets = append(targets, &trident.TargetResponse{
			Instance:   &tk.Instance,
			Job:        &tk.Job,
			InstanceId: proto.Uint32(uint32(tInstanceID)),
			JobId:      proto.Uint32(uint32(tJobID)),
			TargetId:   proto.Uint32(uint32(targetID)),
		})
		return true
	})
	return targets, err
}

func (e *Synchronizer) prepare(req *trident.PrometheusLabelRequest) error {
	metricNamesToE := mapset.NewSet[string]()
	labelNamesToE := mapset.NewSet[string]()
	labelValuesToE := mapset.NewSet[string]()
	metricAPPLabelLayoutsToE := mapset.NewSet[cache.LayoutKey]()
	labelsToAdd := mapset.NewSet[cache.LabelKey]()
	metricLabelsToAdd := make(map[string]mapset.Set[cache.MetricLabelDetailKey], 0)
	metricTargetsToAdd := mapset.NewSet[cache.MetricTargetKey]()
	for _, m := range req.GetRequestLabels() {
		mn := m.GetMetricName()
		e.tryAppendMetricNameToEncode(metricNamesToE, mn)
		var instanceValue string
		var jobValue string
		for _, l := range m.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			e.tryAppendLabelNameToEncode(labelNamesToE, ln)
			e.tryAppendLabelValueToEncode(labelValuesToE, lv)
			if ln == TargetLabelInstance {
				instanceValue = l.GetValue()
			} else if ln == TargetLabelJob {
				jobValue = l.GetValue()
			}
			e.tryAppendLabelToAdd(labelsToAdd, ln, lv)
			e.tryAppendMetricLabelToAdd(metricLabelsToAdd, mn, ln, lv)
		}
		targetID, ok := e.cache.Target.GetIDByKey(cache.NewTargetKey(instanceValue, jobValue))
		for _, l := range m.GetLabels() {
			ln := l.GetName()
			if ln == TargetLabelInstance || ln == TargetLabelJob {
				continue
			}
			e.tryAppendMetricAPPLabelLayoutToEncode(metricAPPLabelLayoutsToE, mn, ln, targetID)
		}
		if ok {
			e.tryAppendMetricTargetToAdd(metricTargetsToAdd, mn, targetID)
		}
	}

	if metricNamesToE.Cardinality() == 0 && labelNamesToE.Cardinality() == 0 && labelValuesToE.Cardinality() == 0 &&
		metricAPPLabelLayoutsToE.Cardinality() == 0 && labelsToAdd.Cardinality() == 0 && len(metricLabelsToAdd) == 0 {
		return nil
	}

	syncResp, err := e.grpcurl.Sync(
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
	eg, ctx := errgroup.WithContext(context.Background())
	AppendErrGroupWithContext(ctx, eg, e.addMetricNameCache, syncResp.GetMetricNames())
	AppendErrGroupWithContext(ctx, eg, e.addLabelNameCache, syncResp.GetLabelNames())
	AppendErrGroupWithContext(ctx, eg, e.addLabelValueCache, syncResp.GetLabelValues())
	AppendErrGroupWithContext(ctx, eg, e.addMetricAPPLabelLayoutCache, syncResp.GetMetricAppLabelLayouts())
	AppendErrGroupWithContext(ctx, eg, e.addLabelCache, syncResp.GetLabels())
	AppendErrGroupWithContext(ctx, eg, e.addMetricLabelCache, metricLabelsToAdd)
	return eg.Wait()
}

func (e *Synchronizer) assemble(req *trident.PrometheusLabelRequest) (*trident.PrometheusLabelResponse, error) {
	resp := new(trident.PrometheusLabelResponse)
	mls, err := e.assembleMetricLabel(req.GetRequestLabels())
	if err != nil {
		return nil, errors.Wrap(err, "assembleMetricLabel")
	}
	resp.ResponseLabelIds = mls
	ts, err := e.assembleTarget(req.GetRequestTargets())
	if err != nil {
		return nil, errors.Wrap(err, "assembleTarget")
	}
	resp.ResponseTargetIds = ts
	return resp, nil
}

func (e *Synchronizer) assembleMetricLabel(mls []*trident.MetricLabelRequest) ([]*trident.MetricLabelResponse, error) {
	respMLs := make([]*trident.MetricLabelResponse, 0)
	for _, ml := range mls {
		mn := ml.GetMetricName()
		mni, ok := e.cache.MetricName.GetIDByName(mn)
		if !ok {
			log.Errorf("metric_name: %s id not found", mn)
			continue
		}

		var rls []*trident.LabelResponse
		for _, l := range ml.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			ni, ok := e.cache.LabelName.GetIDByName(ln)
			if !ok {
				log.Errorf("label_name: %s id not found", ln)
				continue
			}
			vi, ok := e.cache.LabelValue.GetIDByValue(lv)
			if !ok {
				log.Errorf("label_value: %s id not found", lv)
				continue
			}
			rls = append(rls, &trident.LabelResponse{
				Name:    &ln,
				NameId:  proto.Uint32(uint32(ni)),
				Value:   &lv,
				ValueId: proto.Uint32(uint32(vi)),
			})
		}
		respMLs = append(respMLs, &trident.MetricLabelResponse{
			MetricName: &mn,
			MetricId:   proto.Uint32(uint32(mni)),
			LabelIds:   rls,
		})
	}
	return respMLs, nil
}

func (e *Synchronizer) assembleTarget(ts []*trident.TargetRequest) ([]*trident.TargetResponse, error) {
	respTs := make([]*trident.TargetResponse, 0)
	for _, t := range ts {
		instance := t.GetInstance()
		job := t.GetJob()
		tID, ok := e.cache.Target.GetIDByKey(cache.NewTargetKey(instance, job))
		if !ok {
			log.Errorf("target instance: %s, job: %s id not found", instance, job)
			continue
		}
		insID, ok := e.cache.LabelValue.GetIDByValue(instance)
		if !ok {
			log.Errorf("instance label_value: %s id not found", instance)
			continue
		}
		jobID, ok := e.cache.LabelValue.GetIDByValue(job)
		if !ok {
			log.Errorf("job label_value: %s id not found", job)
			continue
		}
		respTs = append(respTs, &trident.TargetResponse{
			Instance:   &instance,
			InstanceId: proto.Uint32(uint32(insID)),
			Job:        &job,
			JobId:      proto.Uint32(uint32(jobID)),
			TargetId:   proto.Uint32(uint32(tID)),
		})
	}
	return respTs, nil
}

func (e *Synchronizer) tryAppendMetricNameToEncode(toEn mapset.Set[string], name string) {
	if _, ok := e.cache.MetricName.GetIDByName(name); !ok {
		toEn.Add(name)
	}
}

func (e *Synchronizer) addMetricNameCache(arg ...interface{}) error {
	mns := arg[0].([]*controller.PrometheusMetricName)
	e.cache.MetricName.Add(mns)
	return nil
}

func (e *Synchronizer) tryAppendLabelNameToEncode(toEn mapset.Set[string], name string) {
	if _, ok := e.cache.LabelName.GetIDByName(name); !ok {
		toEn.Add(name)
	}
}

func (e *Synchronizer) addLabelNameCache(arg ...interface{}) error {
	lns := arg[0].([]*controller.PrometheusLabelName)
	e.cache.LabelName.Add(lns)
	return nil
}

func (e *Synchronizer) tryAppendLabelValueToEncode(toEn mapset.Set[string], name string) {
	if _, ok := e.cache.LabelValue.GetIDByValue(name); !ok {
		toEn.Add(name)
	}
}

func (e *Synchronizer) addLabelValueCache(arg ...interface{}) error {
	lvs := arg[0].([]*controller.PrometheusLabelValue)
	e.cache.LabelValue.Add(lvs)
	return nil
}

func (e *Synchronizer) tryAppendMetricAPPLabelLayoutToEncode(toEn mapset.Set[cache.LayoutKey], metricName, labelName string, targetID int) {
	targetLabelNameToValue := e.cache.Target.GetLabelNameToValueByID(targetID)
	for tln := range targetLabelNameToValue {
		if tln == labelName {
			return
		}
	}
	k := cache.NewLayoutKey(metricName, labelName)
	if _, ok := e.cache.MetricAndAPPLabelLayout.GetIndexByKey(k); !ok {
		toEn.Add(k)
	}
}

func (e *Synchronizer) addMetricAPPLabelLayoutCache(arg ...interface{}) error {
	ls := arg[0].([]*controller.PrometheusMetricAPPLabelLayout)
	e.cache.MetricAndAPPLabelLayout.Add(ls)
	return nil
}

func (e *Synchronizer) tryAppendLabelToAdd(toAdd mapset.Set[cache.LabelKey], name, value string) {
	if ok := e.cache.Label.IfKeyExists(cache.NewLabelKey(name, value)); !ok {
		toAdd.Add(cache.NewLabelKey(name, value))
	}
}

func (e *Synchronizer) addLabelCache(arg ...interface{}) error {
	ls := arg[0].([]*controller.PrometheusLabel)
	e.cache.Label.Add(ls)
	return nil
}

func (e *Synchronizer) tryAppendMetricLabelToAdd(toAdd map[string]mapset.Set[cache.MetricLabelDetailKey], metricName, labelName, labelValue string) {
	mlk := cache.NewMetricLabelDetailKey(metricName, labelName, labelValue)
	if ok := e.cache.MetricLabel.IfKeyExists(mlk); !ok {
		if _, ok := toAdd[metricName]; !ok {
			toAdd[metricName] = mapset.NewSet[cache.MetricLabelDetailKey]()
		}
		toAdd[metricName].Add(mlk)
	}
}

func (e *Synchronizer) addMetricLabelCache(arg ...interface{}) error {
	m := arg[0].(map[string]mapset.Set[cache.MetricLabelDetailKey])
	for _, ks := range m {
		e.cache.MetricLabel.Add(ks.ToSlice())
	}
	return nil
}

func (e *Synchronizer) tryAppendMetricTargetToAdd(toAdd mapset.Set[cache.MetricTargetKey], metricName string, targetID int) {
	if ok := e.cache.MetricTarget.IfKeyExists(cache.NewMetricTargetKey(metricName, targetID)); !ok {
		toAdd.Add(cache.NewMetricTargetKey(metricName, targetID))
	}
}

func (e *Synchronizer) addMetricTargetCache(arg ...interface{}) error {
	ts := arg[0].([]cache.MetricTargetKey)
	e.cache.MetricTarget.Add(ts)
	return nil
}
