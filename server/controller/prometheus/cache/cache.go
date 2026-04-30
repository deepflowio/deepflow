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

	"golang.org/x/sync/errgroup"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

var log = logger.MustGetLogger("prometheus.synchronizer.cache")

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
	org, err := common.NewORG(orgID)
	if err != nil {
		log.Errorf("failed to create org object: %s", orgID, err.Error())
		return nil, err
	}
	log.Infof("new prometheus cache", org.LogPrefix)
	mn := newMetricName(org)
	ln := newLabelName(org)
	lv := newLabelValue(org)
	c := &Cache{
		org:                     org,
		canRefresh:              make(chan bool, 1),
		MetricName:              mn,
		LabelName:               ln,
		LabelValue:              lv,
		MetricAndAPPLabelLayout: newMetricAndAPPLabelLayout(org),
		Label:                   newLabel(org, ln, lv),
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
			log.Infof("last refresh cache not completed now", c.org.LogPrefix)
		}
	}
	return
}

func (c *Cache) refresh() error {
	log.Infof("refresh cache started", c.org.LogPrefix)
	// LabelName and LabelValue must be refreshed before Label,
	// because Label.refresh() converts name/value strings to IDs.
	egRunAhead := &errgroup.Group{}
	common.AppendErrGroup(egRunAhead, c.MetricName.refresh)
	common.AppendErrGroup(egRunAhead, c.LabelName.refresh)
	common.AppendErrGroup(egRunAhead, c.LabelValue.refresh)
	if err := egRunAhead.Wait(); err != nil {
		return err
	}
	eg := &errgroup.Group{}
	common.AppendErrGroup(eg, c.Label.refresh)
	common.AppendErrGroup(eg, c.MetricAndAPPLabelLayout.refresh)
	err := eg.Wait()
	log.Infof("refresh cache completed", c.org.LogPrefix)
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
		for k, v := range tempCache.MetricName.GetNameToID() {
			temp["name_to_id"].(map[string]interface{})[k] = v
		}
		if len(temp["name_to_id"].(map[string]interface{})) > 0 {
			content["metric_name"] = temp
		}
	}
	getLabelName := func() {
		temp := map[string]interface{}{
			"name_to_id": make(map[string]interface{}),
		}
		for k, v := range tempCache.LabelName.GetNameToID() {
			temp["name_to_id"].(map[string]interface{})[k] = v
		}
		if len(temp["name_to_id"].(map[string]interface{})) > 0 {
			content["label_name"] = temp
		}
	}
	getLabelValue := func() {
		temp := map[string]interface{}{
			"value_to_id": make(map[string]interface{}),
		}

		for key, value := range tempCache.LabelValue.GetValueToID() {
			temp["value_to_id"].(map[string]interface{})[key] = value
		}

		if len(temp["value_to_id"].(map[string]interface{})) > 0 {
			content["label_value"] = temp
		}
	}
	getMetricAndAppLabelLayout := func() {
		temp := map[string]interface{}{
			"layout_key_to_index": make(map[string]interface{}),
		}
		for k, v := range tempCache.MetricAndAPPLabelLayout.GetLayoutKeyToIndex() {
			temp["layout_key_to_index"].(map[string]interface{})[marshal(k)] = v
		}
		if len(temp["layout_key_to_index"].(map[string]interface{})) > 0 {
			content["metric_and_app_label_layout"] = temp
		}
	}
	getLabel := func() {
		temp := map[string]interface{}{
			"key_to_id": make(map[string]interface{}),
		}
		for key, value := range tempCache.Label.GetKeyToID() {
			temp["key_to_id"].(map[string]interface{})[key.String()] = value
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
