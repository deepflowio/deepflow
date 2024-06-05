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

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/message/controller"
	// . "github.com/deepflowio/deepflow/server/controller/prometheus/common"
	"github.com/deepflowio/deepflow/server/controller/prometheus/config"
)

var log = logging.MustGetLogger("prometheus.synchronizer.cache")

var (
	cacheOnce sync.Once
	cacheIns  *Cache
)

type cacheRefresher interface {
	refresh() error
}

type Cache struct {
	ctx context.Context

	canRefresh      chan bool
	refreshInterval time.Duration

	MetricName              *metricName
	LabelName               *labelName
	LabelValue              *labelValue
	MetricAndAPPLabelLayout *metricAndAPPLabelLayout
	Target                  *target
	Label                   *label
	MetricLabel             *metricLabel
	MetricTarget            *metricTarget
}

func GetSingleton() *Cache {
	cacheOnce.Do(func() {
		mn := newMetricName()
		l := newLabel()
		t := newTarget()
		cacheIns = &Cache{
			canRefresh:              make(chan bool, 1),
			MetricName:              mn,
			LabelName:               newLabelName(),
			LabelValue:              newLabelValue(),
			MetricAndAPPLabelLayout: newMetricAndAPPLabelLayout(),
			Target:                  t,
			Label:                   l,
			MetricLabel:             newMetricLabel(mn, l),
			MetricTarget:            newMetricTarget(mn, t),
		}
	})
	return cacheIns
}

func (c *Cache) Init(ctx context.Context, cfg *config.Config) {
	c.ctx = ctx
	c.refreshInterval = time.Duration(cfg.SynchronizerCacheRefreshInterval) * time.Second
}

func (c *Cache) Start(ctx context.Context, cfg *config.Config) error {
	c.Init(ctx, cfg)
	c.canRefresh <- true
	if err := c.tryRefresh(); err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(c.refreshInterval)
		for {
			select {
			case <-ticker.C:
				c.tryRefresh()
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

func (c *Cache) tryRefresh() (err error) {
LOOP:
	for {
		select {
		case <-c.canRefresh:
			err = c.refresh()
			c.canRefresh <- true
			break LOOP
		default:
			time.Sleep(time.Second)
			log.Info("last refresh cache not completed now")
		}
	}
	return
}

func (c *Cache) refresh() error {
	log.Info("refresh cache started")
	var err error
	for _, r := range []cacheRefresher{
		c.MetricName,
		c.Label,
		c.Target,
		c.LabelName,
		c.LabelValue,
		c.MetricAndAPPLabelLayout,
		c.MetricLabel,
		c.MetricTarget,
	} {
		if e := r.refresh(); e != nil {
			log.Errorf("refresh cache failed: %s", e)
			err = e
		}
	}
	// egRunAhead := &errgroup.Group{}
	// AppendErrGroup(egRunAhead, c.MetricName.refresh)
	// AppendErrGroup(egRunAhead, c.Label.refresh)
	// AppendErrGroup(egRunAhead, c.Target.refresh)
	// egRunAhead.Wait()
	// eg := &errgroup.Group{}
	// c.Label.refresh()
	// AppendErrGroup(eg, c.LabelName.refresh)
	// AppendErrGroup(eg, c.LabelValue.refresh)
	// AppendErrGroup(eg, c.MetricAndAPPLabelLayout.refresh)
	// AppendErrGroup(eg, c.MetricLabel.refresh)
	// AppendErrGroup(eg, c.MetricTarget.refresh)
	// err := eg.Wait()
	log.Info("refresh cache completed")
	return err
}

func GetDebugCache(t controller.PrometheusCacheType) []byte {
	tempCache := GetSingleton()
	content := make(map[string]interface{})

	marshal := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			log.Error(err)
		}
		return string(b)
	}
	getMetricName := func() {
		temp := map[string]interface{}{
			"name_to_id": make(map[string]interface{}),
		}
		for iter := range tempCache.MetricName.nameToID.Iter() {
			temp["name_to_id"].(map[string]interface{})[iter.Key] = iter.Val
		}
		if len(temp["name_to_id"].(map[string]interface{})) > 0 {
			content["metric_name"] = temp
		}
	}
	getLabelName := func() {
		temp := map[string]interface{}{
			"name_to_id": make(map[string]interface{}),
		}
		for iter := range tempCache.LabelName.nameToID.Iter() {
			temp["name_to_id"].(map[string]interface{})[iter.Key] = iter.Val
		}
		if len(temp["name_to_id"].(map[string]interface{})) > 0 {
			content["label_name"] = temp
		}
	}
	getLabelValue := func() {
		temp := map[string]interface{}{
			"value_to_id": make(map[string]interface{}),
		}
		for iter := range tempCache.LabelValue.valueToID.Iter() {
			temp["value_to_id"].(map[string]interface{})[iter.Key] = iter.Val
		}
		if len(temp["value_to_id"].(map[string]interface{})) > 0 {
			content["label_value"] = temp
		}
	}
	getMetricAndAppLabelLayout := func() {
		temp := map[string]interface{}{
			"layout_key_to_index": make(map[string]interface{}),
		}
		for iter := range tempCache.MetricAndAPPLabelLayout.layoutKeyToIndex.Iter() {
			temp["layout_key_to_index"].(map[string]interface{})[iter.Key.String()] = iter.Val
		}
		if len(temp["layout_key_to_index"].(map[string]interface{})) > 0 {
			content["metric_and_app_label_layout"] = temp
		}
	}
	getTarget := func() {
		temp := map[string]interface{}{
			"key_to_target_id":         make(map[string]interface{}),
			"target_id_to_label_names": make(map[string]interface{}),
		}
		for key, value := range tempCache.Target.keyToTargetID.Get() {
			k, _ := json.Marshal(key)
			temp["key_to_target_id"].(map[string]interface{})[string(k)] = value
		}
		for key, value := range tempCache.Target.targetIDToLabelNames.Get() {
			keys := make(map[string]interface{})
			for item := range value.Iterator().C {
				keys[marshal(item)] = struct{}{}
			}
			temp["target_id_to_label_names"].(map[string]interface{})[fmt.Sprintf("%d", key)] = keys
		}
		if len(temp["key_to_target_id"].(map[string]interface{})) > 0 ||
			len(temp["target_id_to_label_names"].(map[string]interface{})) > 0 {
			content["target"] = temp
		}
	}
	getLabel := func() {
		temp := map[string]interface{}{
			"key_to_id": make(map[string]interface{}),
			"id_to_key": make(map[StringInt]interface{}),
		}
		for iter := range tempCache.Label.keyToID.Iter() {
			temp["key_to_id"].(map[string]interface{})[iter.Key.String()] = iter.Val
		}
		for iter := range tempCache.Label.idToKey.Iter() {
			temp["id_to_key"].(map[StringInt]interface{})[iter.Key] = iter.Val
		}

		if len(temp["key_to_id"].(map[string]interface{})) > 0 ||
			len(temp["id_to_key"].(map[int]interface{})) > 0 {
			content["label"] = temp
		}
	}
	getMetricLabel := func() {
		temp := map[string]interface{}{
			"metric_name_id_to_label_ids": make(map[int][]int),
		}

		tempCache.MetricLabel.metricNameIDToLabelIDs.Range(func(i int, s mapset.Set[int]) bool {
			temp["metric_name_id_to_label_ids"].(map[int][]int)[i] = s.ToSlice()
			return true
		})

		if len(temp["metric_name_id_to_label_ids"].(map[int][]int)) > 0 {
			content["metric_label"] = temp
		}
	}
	getMetricTarget := func() {
		temp := map[string]interface{}{
			"metric_target_keys":        make(map[string]interface{}),
			"metric_name_to_target_ids": make(map[string]interface{}),
			"target_id_to_metric_ids":   make(map[int][]uint32),
		}
		for elem := range tempCache.MetricTarget.metricTargetKeys.Iterator().C {
			temp["metric_target_keys"].(map[string]interface{})[marshal(elem)] = struct{}{}
		}
		for k, v := range tempCache.MetricTarget.targetIDToMetricIDs {
			temp["target_id_to_metric_ids"].(map[int][]uint32)[k] = v
		}
		for key, value := range tempCache.MetricTarget.metricNameToTargetIDs.Get() {
			keys := make(map[string]interface{})
			for item := range value.Iterator().C {
				keys[marshal(item)] = struct{}{}
			}
			temp["metric_name_to_target_ids"].(map[string]interface{})[key] = keys
		}
		if len(temp["metric_target_keys"].(map[string]interface{})) > 0 ||
			len(temp["metric_name_to_target_ids"].(map[string]interface{})) > 0 ||
			len(temp["target_id_to_metric_ids"].(map[int][]uint32)) > 0 {
			content["metric_target"] = temp
		}
	}

	switch t {
	case controller.PrometheusCacheType_ALL:
		getMetricName()
		getLabelName()
		getLabelValue()
		getMetricAndAppLabelLayout()
		getTarget()
		getLabel()
		getMetricLabel()
		getMetricTarget()
	case controller.PrometheusCacheType_METRIC_NAME:
		getMetricName()
	case controller.PrometheusCacheType_LABEL_NAME:
		getLabelName()
	case controller.PrometheusCacheType_LABEL_VALUE:
		getLabelValue()
	case controller.PrometheusCacheType_METRIC_AND_APP_LABEL_LAYOUT:
		getMetricAndAppLabelLayout()
	case controller.PrometheusCacheType_TARGET:
		getTarget()
	case controller.PrometheusCacheType_LABEL:
		getLabel()
	case controller.PrometheusCacheType_METRIC_LABEL:
		getMetricLabel()
	case controller.PrometheusCacheType_METRIC_TARGET:
		getMetricTarget()
	default:
		log.Errorf("%s is not supported", t)
		return nil
	}

	b, err := json.MarshalIndent(content, "", "	")
	if err != nil {
		log.Error(err)
	}
	return b
}
