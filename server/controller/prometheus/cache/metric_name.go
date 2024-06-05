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
	cmap "github.com/orcaman/concurrent-map/v2"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type metricName struct {
	nameToID cmap.ConcurrentMap[string, int]
	idToName cmap.ConcurrentMap[StringInt, string]
}

func newMetricName() *metricName {
	return &metricName{
		nameToID: cmap.New[int](),
		idToName: cmap.NewStringer[StringInt, string](),
	}
}

func (mn *metricName) GetNameToID() cmap.ConcurrentMap[string, int] {
	return mn.nameToID
}

func (mn *metricName) GetIDByName(n string) (int, bool) {
	if id, ok := mn.nameToID.Get(n); ok {
		return id, true
	}
	return 0, false
}

func (mn *metricName) GetNameByID(id int) (string, bool) {
	if name, ok := mn.idToName.Get(StringInt(id)); ok {
		return name, true
	}
	return "", false
}

func (mn *metricName) Add(batch []*controller.PrometheusMetricName) {
	for _, item := range batch {
		mn.nameToID.Set(item.GetName(), int(item.GetId()))
		mn.idToName.Set(StringInt(item.GetId()), item.GetName())
	}
}

func (mn *metricName) refresh() error {
	metricNames, err := mn.load()
	if err != nil {
		return err
	}
	for _, item := range metricNames {
		mn.nameToID.Set(item.Name, item.ID)
		mn.idToName.Set(StringInt(item.ID), item.Name)
	}
	return nil
}

func (mn *metricName) load() ([]*mysql.PrometheusMetricName, error) {
	var metricNames []*mysql.PrometheusMetricName
	err := mysql.Db.Find(&metricNames).Error
	return metricNames, err
}
