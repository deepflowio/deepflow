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
	"sync"

	"github.com/cornelk/hashmap"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

type labelName struct {
	org *common.ORG

	nameToID sync.Map
	idToName *hashmap.Map[int, string]
}

func newLabelName(org *common.ORG) *labelName {
	return &labelName{
		org:      org,
		idToName: hashmap.New[int, string](),
	}
}

func (ln *labelName) GetIDByName(n string) (int, bool) {
	if id, ok := ln.nameToID.Load(n); ok {
		return id.(int), true
	}
	return 0, false
}

func (ln *labelName) GetNameByID(id int) (string, bool) {
	if name, ok := ln.idToName.Get(id); ok {
		return name, true
	}
	return "", false
}

func (ln *labelName) Add(batch []*controller.PrometheusLabelName) {
	for _, item := range batch {
		ln.nameToID.Store(item.GetName(), int(item.GetId()))
		ln.idToName.Set(int(item.GetId()), item.GetName())
	}
}

func (ln *labelName) refresh(args ...interface{}) error {
	labelNames, err := ln.load()
	if err != nil {
		return err
	}
	for _, item := range labelNames {
		ln.nameToID.Store(item.Name, item.ID)
		ln.idToName.Set(item.ID, item.Name)
	}
	return nil
}

func (ln *labelName) load() ([]*mysql.PrometheusLabelName, error) {
	var labelNames []*mysql.PrometheusLabelName
	err := ln.org.DB.Find(&labelNames).Error
	return labelNames, err
}
