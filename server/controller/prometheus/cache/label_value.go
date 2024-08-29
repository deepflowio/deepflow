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
	"github.com/cornelk/hashmap"

	"github.com/deepflowio/deepflow/message/controller"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

type labelValue struct {
	org *common.ORG

	valueToID *hashmap.Map[string, int]
}

func newLabelValue(org *common.ORG) *labelValue {
	return &labelValue{
		org:       org,
		valueToID: hashmap.New[string, int](),
	}
}

func (lv *labelValue) GetIDByValue(v string) (int, bool) {
	if id, ok := lv.valueToID.Get(v); ok {
		return id, true
	}
	return 0, false
}

func (lv *labelValue) GetValueToID() *hashmap.Map[string, int] {
	return lv.valueToID
}

func (lv *labelValue) Add(batch []*controller.PrometheusLabelValue) {
	for _, item := range batch {
		lv.valueToID.Set(item.GetValue(), int(item.GetId()))
	}
}

func (lv *labelValue) refresh(args ...interface{}) error {
	labelValues, err := lv.load()
	if err != nil {
		return err
	}
	for _, item := range labelValues {
		lv.valueToID.Set(item.Value, item.ID)
	}
	return nil
}

func (lv *labelValue) load() ([]*mysqlmodel.PrometheusLabelValue, error) {
	var labelValues []*mysqlmodel.PrometheusLabelValue
	err := lv.org.DB.Find(&labelValues).Error
	return labelValues, err
}
