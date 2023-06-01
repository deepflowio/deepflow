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
	"sync"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type labelValue struct {
	valueToID sync.Map
}

func (t *labelValue) GetIDByValue(v string) (int, bool) {
	if id, ok := t.valueToID.Load(v); ok {
		return id.(int), true
	}
	return 0, false
}

func (t *labelValue) Add(batch []*controller.PrometheusLabelValue) {
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
