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
	"github.com/deepflowio/deepflow/server/controller/common"
	. "github.com/deepflowio/deepflow/server/controller/side/prometheus/common"
)

var log = logging.MustGetLogger("side.prometheus")

type Encoder struct {
	cache   *Cache
	grpcurl *GRPCURL
}

func NewEncoder() *Encoder {
	return &Encoder{
		cache:   GetSingletonCache(),
		grpcurl: new(GRPCURL),
	}
}

func (e *Encoder) Encode(metrics []*trident.MetricLabelRequest) ([]*trident.MetricLabelResponse, error) {
	if len(metrics) == 0 {
		return e.assembleFully()
	}
	err := e.prepare(metrics)
	if err != nil {
		log.Errorf("prepare error: %+v", err)
		return nil, err
	}
	return e.assemble(metrics)
}

func (e *Encoder) assembleFully() ([]*trident.MetricLabelResponse, error) {
	defer e.cache.clear()
	err := e.cache.refreshFully()
	if err != nil {
		return nil, err
	}
	var res []*trident.MetricLabelResponse
	e.cache.metricName.nameToID.Range(func(k, v interface{}) bool {
		var labels []*trident.LabelIDResponse
		metricName := k.(string)
		metricID := v.(int)
		for _, labelName := range e.cache.metricAndAPPLabelLayout.metricNameToAPPLabelNames[metricName] {
			labelNameID, ok := e.cache.labelName.getIDByName(labelName)
			if !ok {
				log.Error("labelNameID not found")
				return false
			}
			labelValue, ok := e.cache.label.getValueByName(labelName)
			if !ok {
				log.Error("labelValue not found")
				return false
			}
			labelValueID, ok := e.cache.labelValue.getValueID(labelValue)
			if !ok {
				log.Error("labelValueID not found")
				return false
			}
			idx, ok := e.cache.metricAndAPPLabelLayout.getIndex(layoutKey{metricName: metricName, labelName: labelName})
			if !ok {
				log.Error("idx not found")
				return false
			}
			label := &trident.LabelIDResponse{
				Name:                &labelName,
				Value:               &labelValue,
				NameId:              proto.Uint32(uint32(labelNameID)),
				ValueId:             proto.Uint32(uint32(labelValueID)),
				AppLabelColumnIndex: proto.Uint32(uint32(idx)),
			}
			labels = append(labels, label)
		}
		targetID, ok := e.cache.metricTarget.getTargetID(metricName)
		if !ok {
			for n, v := range e.cache.target.targetIDToLabelNameToValue[targetID] {
				nID, ok := e.cache.labelName.getIDByName(n)
				if !ok {
					log.Error("labelNameID not found")
					return false
				}
				vID, ok := e.cache.labelValue.getValueID(v)
				if !ok {
					log.Error("labelValueID not found")
					return false
				}
				label := &trident.LabelIDResponse{
					Name:                &n,
					Value:               &v,
					NameId:              proto.Uint32(uint32(nID)),
					ValueId:             proto.Uint32(uint32(vID)),
					AppLabelColumnIndex: proto.Uint32(uint32(0)),
				}
				labels = append(labels, label)
			}
		}
		metric := &trident.MetricLabelResponse{
			MetricName: &metricName,
			MetricId:   proto.Uint32(uint32((metricID))),
			TargetId:   proto.Uint32(uint32(targetID)),
			LabelIds:   labels,
		}
		res = append(res, metric)
		return true
	})
	return res, nil
}

func (e *Encoder) prepare(metrics []*trident.MetricLabelRequest) error {
	metricNamesToE := mapset.NewSet[string]()
	labelNamesToE := mapset.NewSet[string]()
	labelValuesToE := mapset.NewSet[string]()
	metricAPPLabelLayoutsToE := mapset.NewSet[layoutKey]()
	labelsToAdd := mapset.NewSet[labelKey]()
	metricTargetsToAdd := mapset.NewSet[metricTargetKey]()
	for _, m := range metrics {
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
			} else if !common.Contains(e.cache.target.labelNames, ln) {
				e.tryAppendMetricAPPLabelLayoutToEncode(metricAPPLabelLayoutsToE, layoutKey{metricName: mn, labelName: ln})
			}
			e.tryAppendLabelToAdd(labelsToAdd, ln, lv)
		}
		e.tryAppendMetricTargetToAdd(metricTargetsToAdd, mn, instanceValue, jobValue)
	}

	if metricNamesToE.Cardinality() == 0 && labelNamesToE.Cardinality() == 0 && labelValuesToE.Cardinality() == 0 && metricAPPLabelLayoutsToE.Cardinality() == 0 && labelsToAdd.Cardinality() == 0 && metricTargetsToAdd.Cardinality() == 0 {
		return nil
	}

	log.Info(metricNamesToE) // TODO delete
	log.Info(labelNamesToE)
	log.Info(labelValuesToE)
	log.Info(metricAPPLabelLayoutsToE)
	log.Info(labelsToAdd)
	log.Info(metricTargetsToAdd)
	syncResp, err := e.grpcurl.Sync(
		&controller.SyncPrometheusRequest{
			MetricNames: metricNamesToE.ToSlice(),
			LabelNames:  labelNamesToE.ToSlice(),
			LabelValues: labelValuesToE.ToSlice(),
			MetricAppLabelLayouts: func(ks []layoutKey) []*controller.PrometheusMetricAPPLabelLayoutRequest {
				res := make([]*controller.PrometheusMetricAPPLabelLayoutRequest, 0, len(ks))
				for i := range ks {
					res = append(res, &controller.PrometheusMetricAPPLabelLayoutRequest{
						MetricName:   &ks[i].metricName,
						AppLabelName: &ks[i].labelName,
					})
				}
				return res
			}(metricAPPLabelLayoutsToE.ToSlice()),
			Labels: func(ks []labelKey) []*controller.PrometheusLabel {
				res := make([]*controller.PrometheusLabel, 0, len(ks))
				for i := range ks {
					res = append(res, &controller.PrometheusLabel{
						Name:  &ks[i].name,
						Value: &ks[i].value,
					})
				}
				return res
			}(labelsToAdd.ToSlice()),
			MetricTargets: func(ks []metricTargetKey) []*controller.PrometheusMetricTarget {
				res := make([]*controller.PrometheusMetricTarget, 0, len(ks))
				for i := range ks {
					res = append(res, &controller.PrometheusMetricTarget{
						MetricName: &ks[i].metricName,
						TargetId:   proto.Uint32(uint32(ks[i].targetID)),
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
	AppendErrGroupWithContext(ctx, eg, e.addMetricTargetCache, syncResp.GetMetricTargets())
	return eg.Wait()
}

func (e *Encoder) assemble(metrics []*trident.MetricLabelRequest) ([]*trident.MetricLabelResponse, error) {
	respMetrics := make([]*trident.MetricLabelResponse, 0, len(metrics))
	for _, m := range metrics {
		mn := m.GetMetricName()
		mni, ok := e.cache.metricName.getIDByName(mn)
		if !ok {
			log.Errorf("metric name id %s not found", mn)
			return nil, errors.Errorf("metric name %s not found", mn)
		}

		var labels []*trident.LabelIDResponse
		for _, l := range m.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			ni, ok := e.cache.labelName.getIDByName(ln)
			if !ok {
				log.Errorf("label name id %s not found", ln)
				return nil, errors.Errorf("label name %s not found", ln)
			}
			vi, ok := e.cache.labelValue.getValueID(lv)
			if !ok {
				log.Errorf("label value id %s not found", lv)
				return nil, errors.Errorf("label value %s not found", lv)
			}
			idx, ok := e.cache.metricAndAPPLabelLayout.getIndex(layoutKey{metricName: mn, labelName: ln})
			if !ok && ln != TargetLabelInstance && ln != TargetLabelJob && !common.Contains(e.cache.target.labelNames, ln) {
				log.Errorf("metric name: %s, label name: %s index not found", mn, ln)
				return nil, errors.Errorf("metric name: %s, label name: %s index not found", mn, ln)
			}
			rl := &trident.LabelIDResponse{
				Name:                &ln,
				NameId:              proto.Uint32(uint32(ni)),
				Value:               &lv,
				ValueId:             proto.Uint32(uint32(vi)),
				AppLabelColumnIndex: proto.Uint32(uint32(idx)),
			}
			labels = append(labels, rl)
		}

		ti, _ := e.cache.metricTarget.getTargetID(mn)
		rm := &trident.MetricLabelResponse{
			MetricName: &mn,
			MetricId:   proto.Uint32(uint32(mni)),
			TargetId:   proto.Uint32(uint32(ti)),
			LabelIds:   labels,
		}
		respMetrics = append(respMetrics, rm)
	}
	return respMetrics, nil
}

func (e *Encoder) tryAppendMetricNameToEncode(toEn mapset.Set[string], name string) {
	if _, ok := e.cache.metricName.getIDByName(name); !ok {
		toEn.Add(name)
	}
}

func (e *Encoder) addMetricNameCache(arg ...interface{}) error {
	mns := arg[0].([]*controller.PrometheusMetricName)
	e.cache.metricName.add(mns)
	return nil
}

func (e *Encoder) tryAppendLabelNameToEncode(toEn mapset.Set[string], name string) {
	if _, ok := e.cache.labelName.getIDByName(name); !ok {
		toEn.Add(name)
	}
}

func (e *Encoder) addLabelNameCache(arg ...interface{}) error {
	lns := arg[0].([]*controller.PrometheusLabelName)
	e.cache.labelName.add(lns)
	return nil
}

func (e *Encoder) tryAppendLabelValueToEncode(toEn mapset.Set[string], name string) {
	if _, ok := e.cache.labelValue.getValueID(name); !ok {
		toEn.Add(name)
	}
}

func (e *Encoder) addLabelValueCache(arg ...interface{}) error {
	lvs := arg[0].([]*controller.PrometheusLabelValue)
	e.cache.labelValue.add(lvs)
	return nil
}

func (e *Encoder) tryAppendMetricAPPLabelLayoutToEncode(toEn mapset.Set[layoutKey], k layoutKey) {
	if _, ok := e.cache.metricAndAPPLabelLayout.getIndex(k); !ok {
		toEn.Add(k)
	}
}

func (e *Encoder) addMetricAPPLabelLayoutCache(arg ...interface{}) error {
	ls := arg[0].([]*controller.PrometheusMetricAPPLabelLayout)
	e.cache.metricAndAPPLabelLayout.add(ls)
	return nil
}

func (e *Encoder) tryAppendLabelToAdd(toAdd mapset.Set[labelKey], name, value string) {
	if _, ok := e.cache.label.getValueByName(name); !ok {
		toAdd.Add(labelKey{name: name, value: value})
	}
}

func (e *Encoder) addLabelCache(arg ...interface{}) error {
	ls := arg[0].([]*controller.PrometheusLabel)
	e.cache.label.add(ls)
	return nil
}

func (e *Encoder) tryAppendMetricTargetToAdd(toAdd mapset.Set[metricTargetKey], metricName, ins, job string) {
	if _, ok := e.cache.metricTarget.getTargetID(metricName); !ok {
		if ti, ok := e.cache.target.getTargetID(ins, job); ok {
			toAdd.Add(metricTargetKey{metricName: metricName, targetID: ti})
		}
	}
}

func (e *Encoder) addMetricTargetCache(arg ...interface{}) error {
	ts := arg[0].([]*controller.PrometheusMetricTarget)
	e.cache.metricTarget.add(ts)
	return nil
}
