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

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/side/prometheus/common"
)

var (
	instanceAndJobKeyJoiner = "-"
	labelJoiner             = ":"
)
var (
	cacheOnce sync.Once
	cacheIns  *Cache
)

type Cache struct {
	ctx context.Context

	canRefresh chan bool

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
			canRefresh:              make(chan bool, 1),
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
	if err := t.refresh(false); err != nil {
		return err
	}
	t.canRefresh <- true
	go func() {
		ticker := time.NewTicker(time.Hour)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				select {
				case t.canRefresh <- true:
					t.refresh(false)
				default:
					log.Info("last refresh cache not completed now")
				}
			}
		}
	}()
	return nil
}

func (t *Cache) refresh(fully bool) error {
	log.Info("refresh cache started")
	eg := &errgroup.Group{}
	AppendErrGroup(eg, t.metricName.refresh, fully)
	AppendErrGroup(eg, t.labelName.refresh, fully)
	AppendErrGroup(eg, t.labelValue.refresh, fully)
	AppendErrGroup(eg, t.metricAndAPPLabelLayout.refresh, fully)
	AppendErrGroup(eg, t.target.refresh, fully)
	AppendErrGroup(eg, t.label.refresh, fully)
	AppendErrGroup(eg, t.metricTarget.refresh, fully)
	err := eg.Wait()
	log.Info("refresh cache completed")
	return err

}

func (t *Cache) refreshFully() error {
	t.clear()
	err := t.refresh(true)
	return err
}

func (t *Cache) clear() {
	t.metricAndAPPLabelLayout.metricNameToAPPLabelNames = make(map[string][]string)
	t.target.targetIDToLabelNameToValue = make(map[int]map[string]string)
}

type metricName struct {
	nameToID sync.Map
}

func (t *metricName) getIDByName(n string) (int, bool) {
	if id, ok := t.nameToID.Load(n); ok {
		return id.(int), true
	}
	return 0, false
}

func (t *metricName) setNameID(n string, id int) {
	t.nameToID.Store(n, id)
}

func (t *metricName) add(batch []*controller.PrometheusMetricName) {
	for _, m := range batch {
		t.nameToID.Store(m.GetName(), int(m.GetId()))
	}
}

func (t *metricName) refresh(args ...interface{}) error {
	metricNames, err := t.load()
	if err != nil {
		return err
	}
	for _, mn := range metricNames {
		t.nameToID.Store(mn.Name, mn.ID)
	}
	return nil
}

func (t *metricName) load() ([]*mysql.PrometheusMetricName, error) {
	var metricNames []*mysql.PrometheusMetricName
	err := mysql.Db.Find(&metricNames).Error
	return metricNames, err
}

type labelName struct {
	nameToID sync.Map
}

func (t *labelName) getIDByName(n string) (int, bool) {
	if id, ok := t.nameToID.Load(n); ok {
		return id.(int), true
	}
	return 0, false
}

func (t *labelName) setNameID(n string, id int) {
	t.nameToID.Store(n, id)
}

func (t *labelName) add(batch []*controller.PrometheusLabelName) {
	for _, m := range batch {
		t.nameToID.Store(m.GetName(), int(m.GetId()))
	}
}

func (t *labelName) refresh(args ...interface{}) error {
	labelNames, err := t.load()
	if err != nil {
		return err
	}
	for _, ln := range labelNames {
		t.nameToID.Store(ln.Name, ln.ID)
	}
	return nil
}

func (t *labelName) load() ([]*mysql.PrometheusLabelName, error) {
	var labelNames []*mysql.PrometheusLabelName
	err := mysql.Db.Find(&labelNames).Error
	return labelNames, err
}

type labelValue struct {
	valueToID sync.Map
}

func (t *labelValue) getValueID(v string) (int, bool) {
	if id, ok := t.valueToID.Load(v); ok {
		return id.(int), true
	}
	return 0, false
}

func (t *labelValue) setValueID(v string, id int) {
	t.valueToID.Store(v, id)
}

func (t *labelValue) add(batch []*controller.PrometheusLabelValue) {
	for _, m := range batch {
		t.valueToID.Store(m.GetValue(), int(m.GetId()))
	}
}

func (t *labelValue) refresh(args ...interface{}) error {
	labelValues, err := t.load()
	if err != nil {
		return err
	}
	for _, lv := range labelValues {
		t.valueToID.Store(lv.Value, lv.ID)
	}
	return nil
}

func (t *labelValue) load() ([]*mysql.PrometheusLabelValue, error) {
	var labelValues []*mysql.PrometheusLabelValue
	err := mysql.Db.Find(&labelValues).Error
	return labelValues, err
}

type layoutKey struct {
	metricName string
	labelName  string
}

type metricAndAPPLabelLayout struct {
	layoutKeyToIndex          sync.Map
	metricNameToAPPLabelNames map[string][]string // only for fully assembled
}

func (t *metricAndAPPLabelLayout) getIndex(key layoutKey) (uint8, bool) {
	if index, ok := t.layoutKeyToIndex.Load(key); ok {
		return index.(uint8), true
	}
	return 0, false
}

func (t *metricAndAPPLabelLayout) setIndex(key layoutKey, index uint8) {
	t.layoutKeyToIndex.Store(key, index)
}

func (t *metricAndAPPLabelLayout) add(batch []*controller.PrometheusMetricAPPLabelLayout) {
	for _, m := range batch {
		t.layoutKeyToIndex.Store(layoutKey{metricName: m.GetMetricName(), labelName: m.GetAppLabelName()}, uint8(m.GetAppLabelColumnIndex()))
	}
}

func (t *metricAndAPPLabelLayout) refresh(args ...interface{}) error {
	metricAPPLabelLayouts, err := t.load()
	if err != nil {
		return err
	}
	fully := args[0].(bool)
	if fully {
		for _, l := range metricAPPLabelLayouts {
			t.layoutKeyToIndex.Store(layoutKey{metricName: l.MetricName, labelName: l.APPLabelName}, uint8(l.APPLabelColumnIndex))
			t.metricNameToAPPLabelNames[l.MetricName] = append(t.metricNameToAPPLabelNames[l.MetricName], l.APPLabelName)
		}
	} else {
		for _, l := range metricAPPLabelLayouts {
			t.layoutKeyToIndex.Store(layoutKey{metricName: l.MetricName, labelName: l.APPLabelName}, uint8(l.APPLabelColumnIndex))
		}
	}
	return nil
}

func (t *metricAndAPPLabelLayout) load() ([]*mysql.PrometheusMetricAPPLabelLayout, error) {
	var metricAPPLabelLayouts []*mysql.PrometheusMetricAPPLabelLayout
	err := mysql.Db.Find(&metricAPPLabelLayouts).Error
	return metricAPPLabelLayouts, err
}

type target struct {
	instanceJobToTargetID      sync.Map // joined key: instance_value + "-" + job_value
	labelNames                 []string
	targetIDToLabelNameToValue map[int]map[string]string // only for fully assembled
}

func (t *target) getTargetID(ins, job string) (int, bool) {
	if id, ok := t.instanceJobToTargetID.Load(ins + instanceAndJobKeyJoiner + job); ok {
		return id.(int), true
	}
	return 0, false
}

func (t *target) getLabelNames() []string {
	return t.labelNames
}

func (t *target) refresh(args ...interface{}) error {
	targets, err := t.load()
	if err != nil {
		return err
	}
	fully := args[0].(bool)
	if fully {
		for _, tg := range targets {
			t.instanceJobToTargetID.Store(strings.Join([]string{tg.Instance, tg.Job}, instanceAndJobKeyJoiner), tg.ID)
			t.targetIDToLabelNameToValue[tg.ID] = t.formatLabels(tg)
		}
	} else {
		for _, tg := range targets {
			t.instanceJobToTargetID.Store(strings.Join([]string{tg.Instance, tg.Job}, instanceAndJobKeyJoiner), tg.ID)
		}
	}
	log.Infof("refreshed targets: %+v", t)
	return nil
}

func (t *target) formatLabels(tg *mysql.PrometheusTarget) (labelNameToValue map[string]string) {
	labelNameToValue = make(map[string]string)
	labelNameToValue[TargetLabelInstance] = tg.Instance
	labelNameToValue[TargetLabelJob] = tg.Job
	for _, l := range strings.Split(tg.OtherLabels, ",") {
		if l == "" {
			continue
		}
		parts := strings.Split(l, labelJoiner)
		if len(parts) != 2 {
			continue
		}
		labelNameToValue[parts[0]] = parts[1]
	}
	return
}

func (t *target) load() ([]*mysql.PrometheusTarget, error) {
	var targets []*mysql.PrometheusTarget
	err := mysql.Db.Find(&targets).Error
	return targets, err
}

type labelKey struct {
	name  string
	value string
}

type label struct {
	nameToValue sync.Map
}

func (t *label) getValueByName(name string) (string, bool) {
	if value, ok := t.nameToValue.Load(name); ok {
		return value.(string), true
	}
	return "", false
}

func (t *label) setNameValue(name, value string) {
	t.nameToValue.Store(name, value)
}

func (t *label) add(batch []*controller.PrometheusLabel) {
	for _, m := range batch {
		t.nameToValue.Store(m.GetName(), m.GetValue())
	}
}

func (t *label) refresh(args ...interface{}) error {
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

type metricTargetKey struct {
	metricName string
	targetID   int
}

type metricTarget struct {
	metricNameToTargetID sync.Map
}

func (t *metricTarget) getTargetID(metricName string) (int, bool) {
	if id, ok := t.metricNameToTargetID.Load(metricName); ok {
		return id.(int), true
	}
	return 0, false
}

func (t *metricTarget) setTargetID(metricName string, id int) {
	t.metricNameToTargetID.Store(metricName, id)
}

func (t *metricTarget) add(batch []*controller.PrometheusMetricTarget) {
	for _, m := range batch {
		t.metricNameToTargetID.Store(m.GetMetricName(), int(m.GetTargetId()))
	}
}

func (t *metricTarget) refresh(args ...interface{}) error {
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
