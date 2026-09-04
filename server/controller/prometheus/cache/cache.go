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
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
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

	refreshInterval time.Duration
	lastRefresh     time.Time

	refreshing  bool
	refreshCond *sync.Cond

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
		refreshCond:             sync.NewCond(&sync.Mutex{}),
		MetricName:              mn,
		LabelName:               ln,
		LabelValue:              lv,
		MetricAndAPPLabelLayout: newMetricAndAPPLabelLayout(org),
		Label:                   newLabel(org, ln, lv),
	}
	return c, nil
}

func (c *Cache) GetORG() *common.ORG {
	return c.org
}

func (c *Cache) GetMetricNameID(name string) (int, bool) {
	return c.MetricName.GetID(name)
}

func (c *Cache) SetMetricNameID(name string, id int) {
	c.MetricName.setID(name, id)
}

func (c *Cache) GetLabelNameID(name string) (int, bool) {
	return c.LabelName.GetID(name)
}

func (c *Cache) GetLabelValueID(value string) (int, bool) {
	return c.LabelValue.GetID(value)
}

func (c *Cache) GetLabelID(name, value string) (int, bool) {
	return c.Label.GetIDByKey(NewLabelKey(name, value))
}

func (c *Cache) GetLabelKeyToID() map[LabelKey]int {
	return c.Label.GetKeyToID()
}

func (c *Cache) GetLabelNameByID(id int) (string, bool) {
	return c.LabelName.GetNameByID(id)
}

func (c *Cache) GetLabelValueByID(id int) (string, bool) {
	return c.LabelValue.GetValueByID(id)
}

func (c *Cache) GetMetricNameToID() map[string]int {
	return c.MetricName.GetNameToID()
}

func (c *Cache) GetMetricAndAPPLabelLayout() map[LayoutKey]uint8 {
	return c.MetricAndAPPLabelLayout.GetLayoutKeyToIndex()
}

func (c *Cache) GetMetricAndAPPLabelLayoutIndex(key LayoutKey) (uint8, bool) {
	return c.MetricAndAPPLabelLayout.GetIndexByKey(key)
}

func (c *Cache) AddMetricAndAPPLabelLayoutsFromGrpc(batch []*controller.PrometheusMetricAPPLabelLayout) {
	c.MetricAndAPPLabelLayout.AddFromGrpc(batch)
}

func (c *Cache) SetLabelNameID(name string, id int) {
	c.LabelName.setID(name, id)
}

func (c *Cache) SetLabelValueID(value string, id int) {
	c.LabelValue.setID(value, id)
}

func (c *Cache) AddMetricNames(batch []*metadbmodel.PrometheusMetricName) {
	c.MetricName.Add(batch)
}

func (c *Cache) AddMetricNamesFromGrpc(batch []*controller.PrometheusMetricName) {
	c.MetricName.AddFromGrpc(batch)
}

func (c *Cache) AddLabelNames(batch []*metadbmodel.PrometheusLabelName) {
	c.LabelName.Add(batch)
}

func (c *Cache) AddLabelNamesFromGrpc(batch []*controller.PrometheusLabelName) {
	c.LabelName.AddFromGrpc(batch)
}

func (c *Cache) AddLabelValues(batch []*metadbmodel.PrometheusLabelValue) {
	c.LabelValue.Add(batch)
}

func (c *Cache) AddLabelValuesFromGrpc(batch []*controller.PrometheusLabelValue) {
	c.LabelValue.AddFromGrpc(batch)
}

func (c *Cache) AddLabels(batch []*metadbmodel.PrometheusLabel) {
	c.Label.Add(batch)
}

func (c *Cache) AddLabelsFromGrpc(batch []*controller.PrometheusLabel) {
	c.Label.AddFromGrpc(batch)
}

func (c *Cache) Refresh(wait bool) error {
	c.refreshCond.L.Lock()
	if c.refreshing {
		if wait {
			// wait for refresh to complete
			for c.refreshing {
				c.refreshCond.Wait()
			}
			c.refreshCond.L.Unlock()
			return nil
		}
		c.refreshCond.L.Unlock()
		return nil
	}

	if !wait && c.refreshInterval > 0 && !c.lastRefresh.IsZero() && time.Since(c.lastRefresh) < c.refreshInterval {
		c.refreshCond.L.Unlock()
		return nil
	}

	c.refreshing = true
	c.refreshCond.L.Unlock()

	err := c.doRefresh()

	c.refreshCond.L.Lock()
	c.refreshing = false
	c.refreshCond.Broadcast()
	c.refreshCond.L.Unlock()
	return err
}

func (c *Cache) doRefresh() error {
	err := c.refresh()
	if err == nil {
		c.lastRefresh = time.Now()
	}
	return err
}

func (c *Cache) refresh() error {
	log.Infof("refresh cache started", c.org.LogPrefix)
	eg := &errgroup.Group{}
	common.AppendErrGroup(eg, c.MetricName.refresh)
	common.AppendErrGroup(eg, c.LabelName.refresh)
	common.AppendErrGroup(eg, c.LabelValue.refresh)
	common.AppendErrGroup(eg, c.MetricAndAPPLabelLayout.refresh)
	err := eg.Wait()
	if err != nil {
		return err
	}
	err = c.Label.refresh()
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
