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
	"gorm.io/gorm/clause"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/message/trident"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/side/prometheus/common"
)

var log = logging.MustGetLogger("controller.side.prometheus")

type Encoder struct {
	cache   *Cache
	grpcurl *GRPCURL
}

func NewEncoder() *Encoder {
	e := &Encoder{
		cache:   GetSingletonCache(),
		grpcurl: new(GRPCURL),
	}
	return e
}

type egFunc func(interface{}) error

func (e *Encoder) Encode(metrics []*trident.MetricLabelRequest) ([]*trident.MetricLabelResponse, error) {
	err := e.prepare(metrics)
	if err != nil {
		return nil, err
	}
	return e.assemble(metrics)
}

func (e *Encoder) prepare(metrics []*trident.MetricLabelRequest) error {
	metricNamesToE := make([]string, 0)
	labelNamesToE := make([]string, 0)
	labelValuesToE := make([]string, 0)
	appLabelIdxKeysToE := make([]appLabelIndexKey, 0)
	labelsToAdd := make([]mysql.PrometheusLabel, 0)
	metricTargetsToAdd := make([]mysql.PrometheusMetricTarget, 0)
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
				e.tryAppendAPPLabelIndexToEncode(appLabelIdxKeysToE, appLabelIndexKey{MetricName: mn, LabelName: ln})
			}
			e.tryAppendLabelToAdd(labelsToAdd, ln, lv)
		}
		e.tryAppendMetricTargetToAdd(metricTargetsToAdd, mn, instanceValue+keyJoiner+jobValue)
	}

	eg, ctx := errgroup.WithContext(context.Background())
	e.addGoToErrGroup(ctx, eg, e.encodeMetricNames, metricNamesToE)
	e.addGoToErrGroup(ctx, eg, e.encodeLabelNames, labelNamesToE)
	e.addGoToErrGroup(ctx, eg, e.encodeLabelValues, labelValuesToE)
	e.addGoToErrGroup(ctx, eg, e.encodeAPPLabelIndex, appLabelIdxKeysToE)
	e.addGoToErrGroup(ctx, eg, e.createLabels, labelsToAdd)
	e.addGoToErrGroup(ctx, eg, e.createMetricTargets, metricTargetsToAdd)
	return eg.Wait()
}

func (e *Encoder) addGoToErrGroup(ctx context.Context, eg *errgroup.Group, f egFunc, arg interface{}) {
	eg.Go(func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return f(arg)
		}
	})
}

func (e *Encoder) assemble(metrics []*trident.MetricLabelRequest) ([]*trident.MetricLabelResponse, error) {
	respMetrics := make([]*trident.MetricLabelResponse, 0, len(metrics))
	for _, m := range metrics {
		mn := m.GetMetricName()
		mni, ok := e.cache.metricName.getIDByName(mn)
		if !ok {
			return nil, errors.Errorf("metric name %s not found", mn)
		}

		var labels []*trident.LabelIDResponse
		for _, l := range m.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			ni, ok := e.cache.labelName.getIDByName(ln)
			if !ok {
				return nil, errors.Errorf("label name %s not found", ln)
			}
			vi, ok := e.cache.labelValue.getValueID(lv)
			if !ok {
				return nil, errors.Errorf("label value %s not found", lv)
			}
			idx, ok := e.cache.metricAndAPPLabelLayout.getIndex(appLabelIndexKey{MetricName: mn, LabelName: ln})
			if !ok {
				return nil, errors.Errorf("metric name %s and label name %s not found", mn, ln)
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

func (e *Encoder) tryAppendMetricNameToEncode(toEn []string, name string) {
	if _, ok := e.cache.metricName.getIDByName(name); !ok {
		toEn = append(toEn, name)
	}
}

func (e *Encoder) encodeMetricNames(arg interface{}) error {
	names := arg.([]string)
	strIDs, err := e.grpcurl.GetIDs(ResourcePrometheusMetricName, names)
	if err != nil {
		return err
	}
	var mns []mysql.PrometheusMetricName
	for _, s := range strIDs {
		mns = append(mns, mysql.PrometheusMetricName{IDField: mysql.IDField{ID: int(s.GetId())}, Name: s.GetStr()})
	}
	err = mysql.Db.Clauses(clause.Insert{Modifier: "IGNORE"}).Create(&mns).Error
	e.cache.metricName.add(mns)
	return err
}

func (e *Encoder) tryAppendLabelNameToEncode(toEn []string, name string) {
	if _, ok := e.cache.labelName.getIDByName(name); !ok {
		toEn = append(toEn, name)
	}
}

func (e *Encoder) encodeLabelNames(arg interface{}) error {
	names := arg.([]string)
	strIDs, err := e.grpcurl.GetIDs(ResourcePrometheusLabelName, names)
	if err != nil {
		return err
	}
	var lns []mysql.PrometheusLabelName
	for _, s := range strIDs {
		lns = append(lns, mysql.PrometheusLabelName{IDField: mysql.IDField{ID: int(s.GetId())}, Name: s.GetStr()})
	}
	err = mysql.Db.Clauses(clause.Insert{Modifier: "IGNORE"}).Create(&lns).Error
	e.cache.labelName.add(lns)
	return err
}

func (e *Encoder) tryAppendLabelValueToEncode(toEn []string, name string) {
	if _, ok := e.cache.labelValue.getValueID(name); !ok {
		toEn = append(toEn, name)
	}
}

func (e *Encoder) encodeLabelValues(arg interface{}) error {
	values := arg.([]string)
	strIDs, err := e.grpcurl.GetIDs(ResourcePrometheusLabelValue, values)
	if err != nil {
		return err
	}
	var lvs []mysql.PrometheusLabelValue
	for _, s := range strIDs {
		lvs = append(lvs, mysql.PrometheusLabelValue{IDField: mysql.IDField{ID: int(s.GetId())}, Value: s.GetStr()})
	}
	err = mysql.Db.Clauses(clause.Insert{Modifier: "IGNORE"}).Create(&lvs).Error
	e.cache.labelValue.add(lvs)
	return err
}

func (e *Encoder) tryAppendAPPLabelIndexToEncode(toEn []appLabelIndexKey, k appLabelIndexKey) {
	if _, ok := e.cache.metricAndAPPLabelLayout.getIndex(k); !ok {
		toEn = append(toEn, k)
	}
}

func (e *Encoder) encodeAPPLabelIndex(arg interface{}) error {
	keys := arg.([]appLabelIndexKey)
	reqIdxs := make([]*controller.PrometheusAPPLabelIndexRequest, 0)
	for _, k := range keys {
		reqIdxs = append(reqIdxs, &controller.PrometheusAPPLabelIndexRequest{MetricName: &k.MetricName, AppLabelName: &k.LabelName})
	}
	respIdxs, err := e.grpcurl.GetAPPLabelIndexes(reqIdxs)
	if err != nil {
		return err
	}

	var idxs []mysql.PrometheusMetricAPPLabelLayout
	for _, idx := range respIdxs {
		idxs = append(idxs, mysql.PrometheusMetricAPPLabelLayout{MetricName: idx.GetMetricName(), APPLabelName: idx.GetAppLabelName(), APPLabelColumnIndex: uint8(idx.GetAppLabelColumnIndex())})
	}
	err = mysql.Db.Clauses(clause.Insert{Modifier: "IGNORE"}).Create(&idxs).Error
	e.cache.metricAndAPPLabelLayout.add(idxs)
	return err
}

func (e *Encoder) tryAppendLabelToAdd(toAdd []mysql.PrometheusLabel, name, value string) {
	if _, ok := e.cache.label.getValueByName(name); !ok {
		toAdd = append(toAdd, mysql.PrometheusLabel{Name: name, Value: value})
	}
}

func (e *Encoder) createLabels(arg interface{}) error {
	ls := arg.([]mysql.PrometheusLabel)
	err := mysql.Db.Clauses(clause.Insert{Modifier: "IGNORE"}).Create(&ls).Error
	e.cache.label.add(ls)
	return err
}

func (e *Encoder) tryAppendMetricTargetToAdd(toAdd []mysql.PrometheusMetricTarget, metricName, targetKey string) {
	if _, ok := e.cache.metricTarget.getTargetID(metricName); !ok {
		if ti, ok := e.cache.target.getTargetID(targetKey); ok {
			toAdd = append(toAdd, mysql.PrometheusMetricTarget{MetricName: metricName, TargetID: ti})
		}
	}
}

func (e *Encoder) createMetricTargets(arg interface{}) error {
	ts := arg.([]mysql.PrometheusMetricTarget)
	err := mysql.Db.Clauses(clause.Insert{Modifier: "IGNORE"}).Create(&ts).Error
	e.cache.metricTarget.add(ts)
	return err
}
