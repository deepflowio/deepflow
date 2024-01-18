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
	cmap "github.com/orcaman/concurrent-map/v2"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type labelValue struct {
	valueToID cmap.ConcurrentMap[string, int]
}

func newLabelValue() *labelValue {
	return &labelValue{
		valueToID: cmap.New[int](),
	}
}

func (lv *labelValue) GetIDByValue(v string) (int, bool) {
	if id, ok := lv.valueToID.Get(v); ok {
		return id, true
	}
	return 0, false
}

func (lv *labelValue) Add(batch []*controller.PrometheusLabelValue) {
	for _, item := range batch {
		lv.valueToID.Set(item.GetValue(), int(item.GetId()))
	}
}

func (lv *labelValue) refresh() error {
	labelValues, err := lv.load()
	if err != nil {
		return err
	}
	for _, item := range labelValues {
		lv.valueToID.Set(item.Value, item.ID)
	}
	return nil
}

func (lv *labelValue) load() ([]*mysql.PrometheusLabelValue, error) {
	var labelValues []*mysql.PrometheusLabelValue
	err := mysql.Db.Find(&labelValues).Error
	return labelValues, err
}
