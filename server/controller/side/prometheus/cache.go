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
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

var keyJoiner = "-"
var (
	cacheOnce sync.Once
	cacheIns  *Cache
)

type Cache struct {
	metricName
	labelName
	labelValue
	metricAndAPPLabelLayout
	target
	label
	metricTarget
}

func GetSingletonCache() *Cache {
	cacheOnce.Do(func() {
		cacheIns = &Cache{
			metricName:              metricName{},
			labelName:               labelName{},
			labelValue:              labelValue{},
			metricAndAPPLabelLayout: metricAndAPPLabelLayout{},
			target:                  target{},
			label:                   label{},
			metricTarget:            metricTarget{},
		}
	})
	return cacheIns
}

func (t *Cache) Start(ctx context.Context) error {
	if err := t.refresh(); err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(time.Hour)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				t.refresh()
			}
		}
	}()
	return nil
}

func (t *Cache) refresh() error {
	log.Info("refresh cache")
	eg := errgroup.Group{}
	eg.Go(t.metricName.refresh)
	eg.Go(t.labelName.refresh)
	eg.Go(t.labelValue.refresh)
	eg.Go(t.metricAndAPPLabelLayout.refresh)
	eg.Go(t.target.refresh)
	eg.Go(t.label.refresh)
	eg.Go(t.metricTarget.refresh)
	return eg.Wait()
}

type metricName struct {
	metricNameToID sync.Map
}

func (t *metricName) getIDByName(n string) (int, bool) {
	id, ok := t.metricNameToID.Load(n)
	return id.(int), ok
}

func (t *metricName) setNameID(n string, id int) {
	t.metricNameToID.Store(n, id)
}

func (t *metricName) add(batch []mysql.PrometheusMetricName) {
	for _, m := range batch {
		t.metricNameToID.Store(m.Name, m.ID)
	}
}

func (t *metricName) refresh() error {
	metricNames, err := t.load()
	if err != nil {
		return err
	}
	for _, mn := range metricNames {
		t.metricNameToID.Store(mn.Name, mn.ID)
	}
	return nil
}

func (t *metricName) load() ([]*mysql.PrometheusMetricName, error) {
	var metricNames []*mysql.PrometheusMetricName
	err := mysql.Db.Find(&metricNames).Error
	return metricNames, err
}

type labelName struct {
	labelNameToID sync.Map
}

func (t *labelName) getIDByName(n string) (int, bool) {
	id, ok := t.labelNameToID.Load(n)
	return id.(int), ok
}

func (t *labelName) setNameID(n string, id int) {
	t.labelNameToID.Store(n, id)
}

func (t *labelName) add(batch []mysql.PrometheusLabelName) {
	for _, m := range batch {
		t.labelNameToID.Store(m.Name, m.ID)
	}
}

func (t *labelName) refresh() error {
	labelNames, err := t.load()
	if err != nil {
		return err
	}
	for _, ln := range labelNames {
		t.labelNameToID.Store(ln.Name, ln.ID)
	}
	return nil
}

func (t *labelName) load() ([]*mysql.PrometheusLabelName, error) {
	var labelNames []*mysql.PrometheusLabelName
	err := mysql.Db.Find(&labelNames).Error
	return labelNames, err
}

type labelValue struct {
	labelValueToID sync.Map
}

func (t *labelValue) getValueID(v string) (int, bool) {
	id, ok := t.labelValueToID.Load(v)
	return id.(int), ok
}

func (t *labelValue) setValueID(v string, id int) {
	t.labelValueToID.Store(v, id)
}

func (t *labelValue) add(batch []mysql.PrometheusLabelValue) {
	for _, m := range batch {
		t.labelValueToID.Store(m.Value, m.ID)
	}
}

func (t *labelValue) refresh() error {
	labelValues, err := t.load()
	if err != nil {
		return err
	}
	for _, lv := range labelValues {
		t.labelValueToID.Store(lv.Value, lv.ID)
	}
	return nil
}

func (t *labelValue) load() ([]*mysql.PrometheusLabelValue, error) {
	var labelValues []*mysql.PrometheusLabelValue
	err := mysql.Db.Find(&labelValues).Error
	return labelValues, err
}

type appLabelIndexKey struct {
	MetricName string
	LabelName  string
}

type metricAndAPPLabelLayout struct {
	metricLabelNameKeyToIndex sync.Map
}

func (t *metricAndAPPLabelLayout) getIndex(key appLabelIndexKey) (uint8, bool) {
	index, ok := t.metricLabelNameKeyToIndex.Load(key)
	return index.(uint8), ok
}

func (t *metricAndAPPLabelLayout) setIndex(key appLabelIndexKey, index uint8) {
	t.metricLabelNameKeyToIndex.Store(key, index)
}

func (t *metricAndAPPLabelLayout) add(batch []mysql.PrometheusMetricAPPLabelLayout) {
	for _, m := range batch {
		t.metricLabelNameKeyToIndex.Store(appLabelIndexKey{MetricName: m.MetricName, LabelName: m.APPLabelName}, m.APPLabelColumnIndex)
	}
}

func (t *metricAndAPPLabelLayout) refresh() error {
	metricAPPLabelLayouts, err := t.load()
	if err != nil {
		return err
	}
	for _, l := range metricAPPLabelLayouts {
		t.metricLabelNameKeyToIndex.Store(strings.Join([]string{l.MetricName, l.APPLabelName}, keyJoiner), l.APPLabelColumnIndex)
	}
	return nil
}

func (t *metricAndAPPLabelLayout) load() ([]*mysql.PrometheusMetricAPPLabelLayout, error) {
	var metricAPPLabelLayouts []*mysql.PrometheusMetricAPPLabelLayout
	err := mysql.Db.Find(&metricAPPLabelLayouts).Error
	return metricAPPLabelLayouts, err
}

type target struct {
	instanceAndJobToTargetID sync.Map // joined key: instance_value + "-" + job_value
	labelNames               []string
}

func (t *target) getTargetID(key string) (int, bool) {
	id, ok := t.instanceAndJobToTargetID.Load(key)
	return id.(int), ok
}

func (t *target) getLabelNames() []string {
	return t.labelNames
}

func (t *target) refresh() error {
	targets, err := t.load()
	if err != nil {
		return err
	}
	for _, tg := range targets {
		t.instanceAndJobToTargetID.Store(strings.Join([]string{tg.Instance, tg.Job}, keyJoiner), tg.ID)
	}
	return nil
}

func (t *target) load() ([]*mysql.PrometheusTarget, error) {
	var targets []*mysql.PrometheusTarget
	err := mysql.Db.Find(&targets).Error
	return targets, err
}

type label struct {
	nameToValue sync.Map
}

func (t *label) getValueByName(name string) (string, bool) {
	value, ok := t.nameToValue.Load(name)
	return value.(string), ok
}

func (t *label) setNameValue(name, value string) {
	t.nameToValue.Store(name, value)
}

func (t *label) add(batch []mysql.PrometheusLabel) {
	for _, m := range batch {
		t.nameToValue.Store(m.Name, m.Value)
	}
}

func (t *label) refresh() error {
	labelNames, err := t.load()
	if err != nil {
		return err
	}
	for _, ln := range labelNames {
		t.nameToValue.Store(ln.Name, ln.Value)
	}
	return nil
}

func (t *label) load() ([]*mysql.PrometheusLabel, error) {
	var labels []*mysql.PrometheusLabel
	err := mysql.Db.Find(&labels).Error
	return labels, err
}

type metricTarget struct {
	metricNameToTargetID sync.Map
}

func (t *metricTarget) getTargetID(metricName string) (int, bool) {
	id, ok := t.metricNameToTargetID.Load(metricName)
	return id.(int), ok
}

func (t *metricTarget) setTargetID(metricName string, id int) {
	t.metricNameToTargetID.Store(metricName, id)
}

func (t *metricTarget) add(batch []mysql.PrometheusMetricTarget) {
	for _, m := range batch {
		t.metricNameToTargetID.Store(m.MetricName, m.TargetID)
	}
}

func (t *metricTarget) refresh() error {
	metricTargets, err := t.load()
	if err != nil {
		return err
	}
	for _, mt := range metricTargets {
		t.metricNameToTargetID.Store(mt.MetricName, mt.TargetID)
	}
	return nil
}

func (t *metricTarget) load() ([]*mysql.PrometheusMetricTarget, error) {
	var metricTargets []*mysql.PrometheusMetricTarget
	err := mysql.Db.Find(&metricTargets).Error
	return metricTargets, err
}
