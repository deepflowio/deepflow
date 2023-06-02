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

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type LabelKey struct {
	Name  string
	Value string
}

func NewLabelKey(name, value string) LabelKey {
	return LabelKey{
		Name:  name,
		Value: value,
	}
}

type label struct {
	keyMap sync.Map
}

func (t *label) GetKey(key LabelKey) bool {
	if _, ok := t.keyMap.Load(key); ok {
		return true
	}
	return false
}

func (t *label) Add(batch []LabelKey) {
	for _, m := range batch {
		t.keyMap.Store(m, struct{}{})
	}
}

func (t *label) refresh(args ...interface{}) error {
	labelKeys, err := t.load()
	if err != nil {
		return err
	}
	for _, lk := range labelKeys {
		t.keyMap.Store(lk, struct{}{})
	}
	return nil
}

func (t *label) load() ([]*mysql.PrometheusLabel, error) {
	var labels []*mysql.PrometheusLabel
	err := mysql.Db.Find(&labels).Error
	return labels, err
}
