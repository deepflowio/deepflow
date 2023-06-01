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
	"sync"
	"time"

	"github.com/op/go-logging"
	"golang.org/x/sync/errgroup"

	"github.com/deepflowio/deepflow/message/controller"
	. "github.com/deepflowio/deepflow/server/controller/side/prometheus/common"
)

var log = logging.MustGetLogger("side.prometheus")

var (
	cacheOnce sync.Once
	cacheIns  *Cache
)

type Cache struct {
	ctx context.Context

	canRefresh chan bool

	MetricName              *metricName
	LabelName               *labelName
	LabelValue              *labelValue
	MetricAndAPPLabelLayout *metricAndAPPLabelLayout
	Target                  *target
	Label                   *label
	MetricTarget            *metricTarget
}

func GetSingletonCache() *Cache {
	cacheOnce.Do(func() {
		tgt := &target{}
		cacheIns = &Cache{
			canRefresh:              make(chan bool, 1),
			MetricName:              &metricName{},
			LabelName:               &labelName{},
			LabelValue:              &labelValue{},
			MetricAndAPPLabelLayout: &metricAndAPPLabelLayout{},
			Target:                  tgt,
			Label:                   &label{},
			MetricTarget:            newMetricTarget(tgt),
		}
	})
	return cacheIns
}

func GetDebugCache(t controller.PrometheusCacheType) []byte {
	tempCache := GetSingletonCache()
	content := make(map[string]interface{})

	getMetricName := func() {
		temp := map[string]interface{}{
			"metric_name_to_id": make(map[string]interface{}),
		}
		tempCache.MetricName.nameToID.Range(func(key, value any) bool {
			temp["metric_name_to_id"].(map[string]interface{})[key.(string)] = value
			return true
		})
		if len(temp["metric_name_to_id"].(map[string]interface{})) > 0 {
			content["metric_name"] = temp
		}
	}
	getLabelName := func() {
		temp := map[string]interface{}{
			"label_name_to_id": make(map[string]interface{}),
		}
		tempCache.LabelName.nameToID.Range(func(key, value any) bool {
			temp["label_name_to_id"].(map[string]interface{})[key.(string)] = value
			return true
		})
		if len(temp["label_name_to_id"].(map[string]interface{})) > 0 {
			content["label_name"] = temp
		}
	}
	getLabelValue := func() {
		temp := map[string]interface{}{
			"label_value_to_id": make(map[string]interface{}),
		}
		tempCache.LabelValue.valueToID.Range(func(key, value any) bool {
			temp["label_value_to_id"].(map[string]interface{})[key.(string)] = value
			return true
		})
		if len(temp["label_value_to_id"].(map[string]interface{})) > 0 {
			content["label_value"] = temp
		}
	}
	getMetricAndAppLabelLayout := func() {
		temp := map[string]interface{}{
			"layout_key_to_index":            make(map[string]interface{}),
			"metric_name_to_app_label_names": make(map[string]interface{}),
		}
		tempCache.MetricAndAPPLabelLayout.layoutKeyToIndex.Range(func(key, value any) bool {
			l := key.(LayoutKey)
			k, _ := json.Marshal(l)
			temp["layout_key_to_index"].(map[string]interface{})[string(k)] = value
			return true
		})
		// TODO: fix this
		// for k, v := range tempCache.MetricAndAPPLabelLayout.metricNameToAPPLabelNames {
		// 	temp["metric_name_to_app_label_names"].(map[string]interface{})[k] = v
		// }
		if len(temp["layout_key_to_index"].(map[string]interface{})) > 0 ||
			len(temp["metric_name_to_app_label_names"].(map[string]interface{})) > 0 {
			content["metric_and_app_label_layout"] = temp
		}
	}
	getTarget := func() {
		temp := map[string]interface{}{
			"key_to_target_id":              make(map[string]interface{}),
			"label_names":                   []string{},
			"target_id_to_label_name_value": make(map[int]map[string]string),
		}
		tempCache.Target.keyToTargetID.Range(func(key, value any) bool {
			t := key.(TargetKey)
			k, _ := json.Marshal(t)
			temp["key_to_target_id"].(map[string]interface{})[string(k)] = value
			return true
		})
		// TODO fix this
		// for _, labelName := range tempCache.Target.labelNames {
		// 	temp["label_names"] = append(temp["label_names"].([]string), labelName)
		// }
		// for id, labelNameToValue := range tempCache.Target.targetIDToLabelNameToValue {
		// 	if temp["target_id_to_label_name_value"].(map[int]map[string]string)[id] == nil {
		// 		temp["target_id_to_label_name_value"].(map[int]map[string]string)[id] = make(map[string]string)
		// 	}
		// 	for labelName, value := range labelNameToValue {
		// 		temp["target_id_to_label_name_value"].(map[int]map[string]string)[id][labelName] = value
		// 	}
		// }
		if len(temp["key_to_target_id"].(map[string]interface{})) > 0 ||
			len(temp["label_names"].([]string)) > 0 ||
			len(temp["target_id_to_label_name_value"].(map[int]map[string]string)) > 0 {
			content["target"] = temp
		}
	}
	getLabel := func() {
		temp := map[string]interface{}{
			"name_to_value": make(map[string]interface{}),
		}
		// TODO fix this
		// tempCache.Label.nameToValue.Range(func(key, value any) bool {
		// 	temp["name_to_value"].(map[string]interface{})[key.(string)] = value
		// 	return true
		// })
		if len(temp["name_to_value"].(map[string]interface{})) > 0 {
			content["label"] = temp
		}
	}
	getMetricTarget := func() {
		temp := map[string]interface{}{
			"metric_name_to_target_id": make(map[string]interface{}),
		}
		// TODO fix this
		// tempCache.MetricTarget.metricNameToTargetID.Range(func(key, value any) bool {
		// 	temp["metric_name_to_target_id"].(map[string]interface{})[key.(string)] = value
		// 	return true
		// })
		if len(temp["metric_name_to_target_id"].(map[string]interface{})) > 0 {
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
	case controller.PrometheusCacheType_METRIC_TARGET:
		getMetricTarget()
	default:
		return nil
	}

	b, _ := json.MarshalIndent(content, "", "	")
	return b
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
	t.Target.refresh()
	eg := &errgroup.Group{}
	AppendErrGroup(eg, t.MetricName.refresh, fully)
	AppendErrGroup(eg, t.LabelName.refresh, fully)
	AppendErrGroup(eg, t.LabelValue.refresh, fully)
	AppendErrGroup(eg, t.MetricAndAPPLabelLayout.refresh, fully)
	AppendErrGroup(eg, t.Label.refresh, fully)
	AppendErrGroup(eg, t.MetricTarget.refresh, fully)
	err := eg.Wait()
	log.Info("refresh cache completed")
	return err

}

func (t *Cache) RefreshFully() error {
	t.Clear()
	err := t.refresh(true)
	return err
}

func (t *Cache) Clear() {
	t.MetricAndAPPLabelLayout.clear()
	t.MetricTarget.clear()
}
