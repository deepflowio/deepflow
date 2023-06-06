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

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/deepflowio/deepflow/message/controller"
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
	keys    mapset.Set[LabelKey]
	idToKey sync.Map
}

func newLabel() *label {
	return &label{
		keys: mapset.NewSet[LabelKey](),
	}
}

func (l *label) IfKeyExists(key LabelKey) bool {
	return l.keys.Contains(key)
}

func (l *label) GetKeyByID(id int) (LabelKey, bool) {
	if item, ok := l.idToKey.Load(id); ok {
		return item.(LabelKey), true
	}
	return LabelKey{}, false
}

func (l *label) Add(batch []*controller.PrometheusLabel) {
	for _, item := range batch {
		l.keys.Add(NewLabelKey(item.GetName(), item.GetValue()))
		l.idToKey.Store(item.GetId(), NewLabelKey(item.GetName(), item.GetValue()))
	}
}

func (l *label) refresh(args ...interface{}) error {
	ls, err := l.load()
	if err != nil {
		return err
	}
	for _, item := range ls {
		l.keys.Add(NewLabelKey(item.Name, item.Value))
		l.idToKey.Store(item.ID, NewLabelKey(item.Name, item.Value))
	}
	return nil
}

func (l *label) load() ([]*mysql.PrometheusLabel, error) {
	var labels []*mysql.PrometheusLabel
	err := mysql.Db.Find(&labels).Error
	return labels, err
}
