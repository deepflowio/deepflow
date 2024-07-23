/**
 * Copyright (c) 2024 Yunshan Networks
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
	"github.com/deepflowio/deepflow/server/controller/tagingestrant/prometheus/common"
)

var log = logging.MustGetLogger("prometheus.synchronizer.cache")

var (
	cacheOnce sync.Once
	cacheIns  *Cache
)

type Cache struct {
	org *common.ORG
	ctx context.Context

	canRefresh      chan bool
	refreshInterval time.Duration

	MetricName              *metricName
	LabelName               *labelName
	LabelValue              *labelValue
	MetricAndAPPLabelLayout *metricAndAPPLabelLayout
	Label                   *label
}

func newCache(orgID int) (*Cache, error) {
	log.Infof("[OID-%d] new prometheus cache", orgID)
	org, err := common.NewORG(orgID)
	if err != nil {
		log.Errorf("[OID-%d] failed to create org object: %s", orgID, err.Error())
		return nil, err
	}
	mn := newMetricName(org)
	c := &Cache{
		org:                     org,
		canRefresh:              make(chan bool, 1),
		MetricName:              mn,
		LabelName:               newLabelName(org),
		LabelValue:              newLabelValue(org),
		MetricAndAPPLabelLayout: newMetricAndAPPLabelLayout(org),
		Label:                   newLabel(org),
	}
	c.canRefresh <- true
	return c, nil
}

func (c *Cache) GetORG() *common.ORG {
	return c.org
}

func (c *Cache) Refresh() (err error) {
LOOP:
	for {
		select {
		case <-c.canRefresh:
			err = c.refresh()
			c.canRefresh <- true
			break LOOP
		default:
			time.Sleep(time.Second)
			log.Info(c.org.Log("last refresh cache not completed now"))
		}
	}
	return
}

func (c *Cache) refresh() error {
	log.Info(c.org.Log("refresh cache started"))
	egRunAhead := &errgroup.Group{}
	common.AppendErrGroup(egRunAhead, c.MetricName.refresh)
	common.AppendErrGroup(egRunAhead, c.Label.refresh)
	egRunAhead.Wait()
	eg := &errgroup.Group{}
	common.AppendErrGroup(eg, c.LabelName.refresh)
	common.AppendErrGroup(eg, c.LabelValue.refresh)
	common.AppendErrGroup(eg, c.MetricAndAPPLabelLayout.refresh)
	err := eg.Wait()
	log.Info(c.org.Log("refresh cache completed"))
	return err

}

func GetDebugCache(t controller.PrometheusCacheType) []byte {
	tempCache, _ := GetCache(1) // TODO add org_id
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
		tempCache.MetricName.nameToID.Range(func(key, value any) bool {
			temp["name_to_id"].(map[string]interface{})[key.(string)] = value
			return true
		})
		if len(temp["name_to_id"].(map[string]interface{})) > 0 {
			content["metric_name"] = temp
		}
	}
	getLabelName := func() {
		temp := map[string]interface{}{
			"name_to_id": make(map[string]interface{}),
		}
		tempCache.LabelName.nameToID.Range(func(key, value any) bool {
			temp["name_to_id"].(map[string]interface{})[key.(string)] = value
			return true
		})
		if len(temp["name_to_id"].(map[string]interface{})) > 0 {
			content["label_name"] = temp
		}
	}
	getLabelValue := func() {
		temp := map[string]interface{}{
			"value_to_id": make(map[string]interface{}),
		}
		tempCache.LabelValue.GetValueToID().Range(func(key string, value int) bool {
			temp["value_to_id"].(map[string]interface{})[key] = value
			return true
		})

		if len(temp["value_to_id"].(map[string]interface{})) > 0 {
			content["label_value"] = temp
		}
	}
	getMetricAndAppLabelLayout := func() {
		temp := map[string]interface{}{
			"layout_key_to_index": make(map[string]interface{}),
		}
		tempCache.MetricAndAPPLabelLayout.layoutKeyToIndex.Range(func(key, value any) bool {
			temp["layout_key_to_index"].(map[string]interface{})[marshal(key)] = value
			return true
		})
		if len(temp["layout_key_to_index"].(map[string]interface{})) > 0 {
			content["metric_and_app_label_layout"] = temp
		}
	}
	getLabel := func() {
		temp := map[string]interface{}{
			"key_to_id": make(map[string]interface{}),
		}
		for iter := range tempCache.Label.keyToID.Iter() {
			temp["key_to_id"].(map[string]interface{})[iter.Key.String()] = iter.Val
		}

		if len(temp["key_to_id"].(map[string]interface{})) > 0 {
			content["label"] = temp
		}
	}
	switch t {
	case controller.PrometheusCacheType_ALL:
		getMetricName()
		getLabelName()
		getLabelValue()
		getMetricAndAppLabelLayout()
		getLabel()
	case controller.PrometheusCacheType_METRIC_NAME:
		getMetricName()
	case controller.PrometheusCacheType_LABEL_NAME:
		getLabelName()
	case controller.PrometheusCacheType_LABEL_VALUE:
		getLabelValue()
	case controller.PrometheusCacheType_METRIC_AND_APP_LABEL_LAYOUT:
		getMetricAndAppLabelLayout()
	case controller.PrometheusCacheType_LABEL:
		getLabel()
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
