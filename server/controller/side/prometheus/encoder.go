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
	Cache   *Cache
	grpcurl *GRPCURL
}

func NewEncoder() *Encoder {
	return &Encoder{
		Cache:   GetSingletonCache(),
		grpcurl: new(GRPCURL),
	}
}

func (e *Encoder) Encode(metrics []*trident.MetricLabelRequest) ([]*trident.MetricLabelResponse, error) {
	err := e.prepare(metrics)
	if err != nil {
		log.Errorf("prepare error: %+v", err)
		return nil, err
	}
	return e.assemble(metrics)
}

func (e *Encoder) prepare(metrics []*trident.MetricLabelRequest) error {
	metricNamesToE := make([]string, 0)
	labelNamesToE := make([]string, 0)
	labelValuesToE := make([]string, 0)
	metricAPPLabelLayoutsToE := make([]*controller.PrometheusMetricAPPLabelLayoutRequest, 0)
	labelsToAdd := make([]*controller.PrometheusLabel, 0)
	metricTargetsToAdd := make([]*controller.PrometheusMetricTarget, 0)
	for _, m := range metrics {
		mn := m.GetMetricName()
		e.tryAppendMetricNameToEncode(&metricNamesToE, mn)
		var instanceValue string
		var jobValue string
		for _, l := range m.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			e.tryAppendLabelNameToEncode(&labelNamesToE, ln)
			e.tryAppendLabelValueToEncode(&labelValuesToE, lv)
			if ln == TargetLabelInstance {
				instanceValue = l.GetValue()
			} else if ln == TargetLabelJob {
				jobValue = l.GetValue()
			} else if !common.Contains(e.Cache.target.labelNames, ln) {
				e.tryAppendMetricAPPLabelLayoutToEncode(&metricAPPLabelLayoutsToE, layoutKey{MetricName: mn, LabelName: ln})
			}
			e.tryAppendLabelToAdd(&labelsToAdd, ln, lv)
		}
		e.tryAppendMetricTargetToAdd(&metricTargetsToAdd, mn, instanceValue+keyJoiner+jobValue)
	}

	log.Info(metricNamesToE) // TODO delete
	log.Info(labelNamesToE)
	log.Info(labelValuesToE)
	log.Info(metricAPPLabelLayoutsToE)
	log.Info(labelsToAdd)
	log.Info(metricTargetsToAdd)

	if len(metricNamesToE) == 0 && len(labelNamesToE) == 0 && len(labelValuesToE) == 0 && len(metricAPPLabelLayoutsToE) == 0 && len(labelsToAdd) == 0 && len(metricTargetsToAdd) == 0 {
		return nil
	}
	syncResp, err := e.grpcurl.Sync(
		&controller.SyncPrometheusRequest{
			MetricNames:           metricNamesToE,
			LabelNames:            labelNamesToE,
			LabelValues:           labelValuesToE,
			MetricAppLabelLayouts: metricAPPLabelLayoutsToE,
			Labels:                labelsToAdd,
			MetricTargets:         metricTargetsToAdd,
		},
	)
	if err != nil {
		return errors.Wrap(err, "grpcurl.Sync")
	}
	eg, ctx := errgroup.WithContext(context.Background())
	AppendErrGroup(ctx, eg, e.encodeMetricNames, syncResp.GetMetricNames())
	AppendErrGroup(ctx, eg, e.encodeLabelNames, syncResp.GetLabelNames())
	AppendErrGroup(ctx, eg, e.encodeLabelValues, syncResp.GetLabelValues())
	AppendErrGroup(ctx, eg, e.encodeAPPLabelIndex, syncResp.GetMetricAppLabelLayouts())
	return eg.Wait()
}

func (e *Encoder) assemble(metrics []*trident.MetricLabelRequest) ([]*trident.MetricLabelResponse, error) {
	respMetrics := make([]*trident.MetricLabelResponse, 0, len(metrics))
	for _, m := range metrics {
		mn := m.GetMetricName()
		mni, ok := e.Cache.metricName.getIDByName(mn)
		if !ok {
			log.Errorf("metric name id %s not found", mn)
			return nil, errors.Errorf("metric name %s not found", mn)
		}

		var labels []*trident.LabelIDResponse
		for _, l := range m.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			ni, ok := e.Cache.labelName.getIDByName(ln)
			if !ok {
				log.Errorf("label name id %s not found", ln)
				return nil, errors.Errorf("label name %s not found", ln)
			}
			vi, ok := e.Cache.labelValue.getValueID(lv)
			if !ok {
				log.Errorf("label value id %s not found", lv)
				return nil, errors.Errorf("label value %s not found", lv)
			}
			idx, ok := e.Cache.metricAndAPPLabelLayout.getIndex(layoutKey{MetricName: mn, LabelName: ln})
			if !ok && ln != TargetLabelInstance && ln != TargetLabelJob && !common.Contains(e.Cache.target.labelNames, ln) {
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

		ti, _ := e.Cache.metricTarget.getTargetID(mn)
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

func (e *Encoder) tryAppendMetricNameToEncode(toEn *[]string, name string) {
	if _, ok := e.Cache.metricName.getIDByName(name); !ok {
		*toEn = append(*toEn, name)
	}
}

func (e *Encoder) encodeMetricNames(arg ...interface{}) error {
	mns := arg[0].([]*controller.PrometheusMetricName)
	e.Cache.metricName.add(mns)
	return nil
}

func (e *Encoder) tryAppendLabelNameToEncode(toEn *[]string, name string) {
	if _, ok := e.Cache.labelName.getIDByName(name); !ok {
		*toEn = append(*toEn, name)
	}
}

func (e *Encoder) encodeLabelNames(arg ...interface{}) error {
	lns := arg[0].([]*controller.PrometheusLabelName)
	e.Cache.labelName.add(lns)
	return nil
}

func (e *Encoder) tryAppendLabelValueToEncode(toEn *[]string, name string) {
	if _, ok := e.Cache.labelValue.getValueID(name); !ok {
		*toEn = append(*toEn, name)
	}
}

func (e *Encoder) encodeLabelValues(arg ...interface{}) error {
	lvs := arg[0].([]*controller.PrometheusLabelValue)
	e.Cache.labelValue.add(lvs)
	return nil
}

func (e *Encoder) tryAppendMetricAPPLabelLayoutToEncode(toEn *[]*controller.PrometheusMetricAPPLabelLayoutRequest, k layoutKey) {
	if _, ok := e.Cache.metricAndAPPLabelLayout.getIndex(k); !ok {
		*toEn = append(*toEn, &controller.PrometheusMetricAPPLabelLayoutRequest{MetricName: &k.MetricName, AppLabelName: &k.LabelName})
	}
}

func (e *Encoder) encodeAPPLabelIndex(arg ...interface{}) error {
	ls := arg[0].([]*controller.PrometheusMetricAPPLabelLayout)
	e.Cache.metricAndAPPLabelLayout.add(ls)
	return nil
}

func (e *Encoder) tryAppendLabelToAdd(toAdd *[]*controller.PrometheusLabel, name, value string) {
	if _, ok := e.Cache.label.getValueByName(name); !ok {
		*toAdd = append(*toAdd, &controller.PrometheusLabel{Name: &name, Value: &value})
	}
}

func (e *Encoder) tryAppendMetricTargetToAdd(toAdd *[]*controller.PrometheusMetricTarget, metricName, targetKey string) {
	if _, ok := e.Cache.metricTarget.getTargetID(metricName); !ok {
		if ti, ok := e.Cache.target.getTargetID(targetKey); ok {
			*toAdd = append(*toAdd, &controller.PrometheusMetricTarget{MetricName: &metricName, TargetId: proto.Uint32(uint32(ti))})
		}
	}
}
