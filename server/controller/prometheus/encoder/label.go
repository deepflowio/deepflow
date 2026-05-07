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

package encoder

import (
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/deepflowio/deepflow/message/controller"
	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

type label struct {
	org          *common.ORG
	lock         sync.Mutex
	resourceType string
	cache        cache.PrometheusCache
}

func newLabel(org *common.ORG) *label {
	c, _ := cache.GetCache(org.ID)
	return &label{
		org:          org,
		resourceType: "label",
		cache:        c,
	}
}

func (l *label) store(item *metadbmodel.PrometheusLabel) {
	l.cache.AddLabels([]*metadbmodel.PrometheusLabel{item})
}

func (l *label) getID(key cache.LabelKey) (int, bool) {
	id, ok := l.cache.GetLabelKeyToID()[key]
	return id, ok
}

func (l *label) refresh(args ...interface{}) error {
	return l.cache.Refresh()
}

func (l *label) encode(toAdd []*controller.PrometheusLabelRequest) ([]*controller.PrometheusLabel, error) {
	l.lock.Lock()
	defer l.lock.Unlock()

	type pendingLabel struct {
		item  *metadbmodel.PrometheusLabel
		name  string
		value string
	}

	resp := make([]*controller.PrometheusLabel, 0)
	var pending []pendingLabel
	for _, item := range toAdd {
		n := item.GetName()
		v := item.GetValue()
		nameID, okN := l.cache.GetLabelNameID(n)
		valueID, okV := l.cache.GetLabelValueID(v)
		if !okN || !okV {
			// Name or value not yet encoded — skip; the next encode round
			// (after the caller retries) will succeed once they are present.
			log.Warningf("label (%s=%s): name_id or value_id not found, skipping", n, v, l.org.LogPrefix)
			continue
		}
		if id, ok := l.getID(cache.NewLabelKey(nameID, valueID)); ok {
			resp = append(resp, &controller.PrometheusLabel{
				Id:    proto.Uint32(uint32(id)),
				Name:  proto.String(n),
				Value: proto.String(v),
			})
			continue
		}
		pending = append(pending, pendingLabel{
			item:  &metadbmodel.PrometheusLabel{NameID: nameID, ValueID: valueID},
			name:  n,
			value: v,
		})
	}

	dbToAdd := make([]*metadbmodel.PrometheusLabel, len(pending))
	for i := range pending {
		dbToAdd[i] = pending[i].item
	}
	if err := addBatch(l.org.DB, dbToAdd, l.resourceType); err != nil {
		log.Errorf("add %s error: %s", l.resourceType, err.Error(), l.org.LogPrefix)
		return nil, err
	}
	for i, p := range pending {
		l.store(dbToAdd[i])
		resp = append(resp, &controller.PrometheusLabel{
			Id:    proto.Uint32(uint32(dbToAdd[i].ID)),
			Name:  proto.String(p.name),
			Value: proto.String(p.value),
		})
	}
	return resp, nil
}
