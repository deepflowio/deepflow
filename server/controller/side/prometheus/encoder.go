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
		log.Errorf("prepare error: %+v", err)
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
			} else if !common.Contains(e.cache.target.labelNames, ln) {
				e.tryAppendAPPLabelIndexToEncode(&appLabelIdxKeysToE, appLabelIndexKey{MetricName: mn, LabelName: ln})
			}
			e.tryAppendLabelToAdd(&labelsToAdd, ln, lv)
		}
		e.tryAppendMetricTargetToAdd(&metricTargetsToAdd, mn, instanceValue+keyJoiner+jobValue)
	}

	log.Info(metricNamesToE) // TODO delete
	log.Info(labelNamesToE)
	log.Info(labelValuesToE)
	log.Info(appLabelIdxKeysToE)
	log.Info(labelsToAdd)
	log.Info(metricTargetsToAdd)
	eg, ctx := errgroup.WithContext(context.Background())
	if len(metricNamesToE) > 0 {
		e.addGoToErrGroup(ctx, eg, e.encodeMetricNames, metricNamesToE)
	}
	if len(labelNamesToE) > 0 {
		e.addGoToErrGroup(ctx, eg, e.encodeLabelNames, labelNamesToE)
	}
	if len(labelValuesToE) > 0 {
		e.addGoToErrGroup(ctx, eg, e.encodeLabelValues, labelValuesToE)
	}
	if len(appLabelIdxKeysToE) > 0 {
		e.addGoToErrGroup(ctx, eg, e.encodeAPPLabelIndex, appLabelIdxKeysToE)
	}
	if len(labelsToAdd) > 0 {
		e.addGoToErrGroup(ctx, eg, e.createLabels, labelsToAdd)
	}
	if len(metricTargetsToAdd) > 0 {
		e.addGoToErrGroup(ctx, eg, e.createMetricTargets, metricTargetsToAdd)
	}
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
	log.Debugf("cache: %+v", e.cache) // TODO delete
	for _, m := range metrics {
		mn := m.GetMetricName()
		mni, ok := e.cache.metricName.getIDByName(mn)
		if !ok {
			log.Error("metric name id %s not found", mn)
			return nil, errors.Errorf("metric name %s not found", mn)
		}

		var labels []*trident.LabelIDResponse
		for _, l := range m.GetLabels() {
			ln := l.GetName()
			lv := l.GetValue()
			ni, ok := e.cache.labelName.getIDByName(ln)
			if !ok {
				log.Error("label name id %s not found", ln)
				return nil, errors.Errorf("label name %s not found", ln)
			}
			vi, ok := e.cache.labelValue.getValueID(lv)
			if !ok {
				log.Error("label value id %s not found", lv)
				return nil, errors.Errorf("label value %s not found", lv)
			}
			idx, ok := e.cache.metricAndAPPLabelLayout.getIndex(appLabelIndexKey{MetricName: mn, LabelName: ln})
			if !ok {
				log.Error("metric name %s and label name %s index not found", mn, ln)
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
	log.Info(respMetrics)
	return respMetrics, nil
}

func (e *Encoder) tryAppendMetricNameToEncode(toEn *[]string, name string) {
	if _, ok := e.cache.metricName.getIDByName(name); !ok {
		*toEn = append(*toEn, name)
	}
}

func (e *Encoder) encodeMetricNames(arg interface{}) error {
	names := mapset.NewSet(arg.([]string)...).ToSlice()
	log.Debugf("encode metric names: %v", names)
	strIDs, err := e.grpcurl.GetIDs(ResourcePrometheusMetricName, names)
	if err != nil {
		return err
	}
	var toAdd []mysql.PrometheusMetricName
	for _, s := range strIDs {
		toAdd = append(toAdd, mysql.PrometheusMetricName{IDField: mysql.IDField{ID: int(s.GetId())}, Name: s.GetStr()})
	}
	count := len(toAdd) // TODO common
	offset := 1000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		mns := toAdd[start:end]
		err = mysql.Db.Create(&mns).Error
		log.Infof("create %s success: %v", ResourcePrometheusMetricName, mns)
		e.cache.metricName.add(mns)
	}
	return nil
}

func (e *Encoder) tryAppendLabelNameToEncode(toEn *[]string, name string) {
	if _, ok := e.cache.labelName.getIDByName(name); !ok {
		*toEn = append(*toEn, name)
	}
}

func (e *Encoder) encodeLabelNames(arg interface{}) error {
	names := mapset.NewSet(arg.([]string)...).ToSlice()
	log.Debugf("encode label names: %v", names)
	strIDs, err := e.grpcurl.GetIDs(ResourcePrometheusLabelName, names)
	if err != nil {
		return err
	}
	var toAdd []mysql.PrometheusLabelName
	for _, s := range strIDs {
		toAdd = append(toAdd, mysql.PrometheusLabelName{IDField: mysql.IDField{ID: int(s.GetId())}, Name: s.GetStr()})
	}
	count := len(toAdd)
	offset := 1000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		lns := toAdd[start:end]
		err = mysql.Db.Create(&lns).Error
		log.Infof("create %s success: %v", ResourcePrometheusLabelName, lns)
		e.cache.labelName.add(lns)
	}
	return nil
}

func (e *Encoder) tryAppendLabelValueToEncode(toEn *[]string, name string) {
	if _, ok := e.cache.labelValue.getValueID(name); !ok {
		*toEn = append(*toEn, name)
	}
}

func (e *Encoder) encodeLabelValues(arg interface{}) error {
	values := mapset.NewSet(arg.([]string)...).ToSlice()
	log.Debugf("encode label values: %v", values) // TODO delete
	strIDs, err := e.grpcurl.GetIDs(ResourcePrometheusLabelValue, values)
	if err != nil {
		return err
	}
	var toAdd []mysql.PrometheusLabelValue
	for _, s := range strIDs {
		toAdd = append(toAdd, mysql.PrometheusLabelValue{IDField: mysql.IDField{ID: int(s.GetId())}, Value: s.GetStr()})
	}
	count := len(toAdd)
	offset := 1000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		lvs := toAdd[start:end]
		err = mysql.Db.Create(&lvs).Error
		log.Infof("create %s success: %v", ResourcePrometheusLabelValue, lvs)
		e.cache.labelValue.add(lvs)
	}
	return nil
}

func (e *Encoder) tryAppendAPPLabelIndexToEncode(toEn *[]appLabelIndexKey, k appLabelIndexKey) {
	if _, ok := e.cache.metricAndAPPLabelLayout.getIndex(k); !ok {
		*toEn = append(*toEn, k)
	}
}

func (e *Encoder) encodeAPPLabelIndex(arg interface{}) error {
	keys := mapset.NewSet(arg.([]appLabelIndexKey)...).ToSlice()
	reqIdxs := make([]*controller.PrometheusAPPLabelIndexRequest, 0)
	for i := range keys { // TODO why must use index
		reqIdxs = append(reqIdxs, &controller.PrometheusAPPLabelIndexRequest{MetricName: &keys[i].MetricName, AppLabelName: &keys[i].LabelName})
	}
	log.Info(keys)
	log.Info(reqIdxs)
	respIdxs, err := e.grpcurl.GetAPPLabelIndexes(reqIdxs)
	if err != nil {
		return err
	}

	var toAdd []mysql.PrometheusMetricAPPLabelLayout
	for _, idx := range respIdxs {
		toAdd = append(toAdd, mysql.PrometheusMetricAPPLabelLayout{MetricName: idx.GetMetricName(), APPLabelName: idx.GetAppLabelName(), APPLabelColumnIndex: uint8(idx.GetAppLabelColumnIndex())})
	}
	count := len(toAdd)
	offset := 1000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		idxs := toAdd[start:end]
		err = mysql.Db.Create(&idxs).Error
		if err != nil {
			log.Error(err)
			return err
		}
		log.Infof("create %s success: %v", ResourcePrometheusMetricAPPLabelLayout, idxs)
		e.cache.metricAndAPPLabelLayout.add(idxs)
	}
	return nil
}

func (e *Encoder) tryAppendLabelToAdd(toAdd *[]mysql.PrometheusLabel, name, value string) {
	if _, ok := e.cache.label.getValueByName(name); !ok {
		*toAdd = append(*toAdd, mysql.PrometheusLabel{Name: name, Value: value})
	}
}

func (e *Encoder) createLabels(arg interface{}) error {
	toAdd := mapset.NewSet(arg.([]mysql.PrometheusLabel)...).ToSlice()
	count := len(toAdd)
	offset := 1000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		ls := toAdd[start:end]
		err := mysql.Db.Create(&ls).Error
		if err != nil {
			log.Info(err)
			err = mysql.Db.Where(ls).Find(&ls).Error
			if err != nil {
				log.Error(err)
				return err
			}
		}
		log.Infof("create %s success: %v", ResourcePrometheusLabel, ls)
		e.cache.label.add(ls)
	}
	return nil
}

func (e *Encoder) tryAppendMetricTargetToAdd(toAdd *[]mysql.PrometheusMetricTarget, metricName, targetKey string) {
	if _, ok := e.cache.metricTarget.getTargetID(metricName); !ok {
		if ti, ok := e.cache.target.getTargetID(targetKey); ok {
			*toAdd = append(*toAdd, mysql.PrometheusMetricTarget{MetricName: metricName, TargetID: ti})
		}
	}
}

func (e *Encoder) createMetricTargets(arg interface{}) error {
	toAdd := mapset.NewSet(arg.([]mysql.PrometheusMetricTarget)...).ToSlice()
	count := len(toAdd)
	offset := 1000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		ts := toAdd[start:end]
		err := mysql.Db.Create(&ts).Error
		if err != nil {
			log.Info(err)
			err = mysql.Db.Where(&ts).Find(&ts).Error
			if err != nil {
				log.Error(err)
				return err
			}
		}
		log.Infof("create %s success: %v", ResourcePrometheusMetricTarget, ts)
		e.cache.metricTarget.add(ts)
	}
	return nil
}
