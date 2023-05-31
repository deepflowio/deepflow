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

type metricName struct {
	nameToID sync.Map
}

func (t *metricName) Get() *sync.Map {
	return &t.nameToID
}

func (t *metricName) GetIDByName(n string) (int, bool) {
	if id, ok := t.nameToID.Load(n); ok {
		return id.(int), true
	}
	return 0, false
}

func (t *metricName) Add(batch []*controller.PrometheusMetricName) {
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
