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
	"context"
	"sync"
	"time"

	"github.com/op/go-logging"
	"golang.org/x/sync/errgroup"

	. "github.com/deepflowio/deepflow/server/controller/prometheus/common"
)

var log = logging.MustGetLogger("prometheus")

var (
	cacheOnce sync.Once
	cacheIns  *Cache
)

type Cache struct {
	ctx context.Context

	canRefresh chan bool

	MetricName              *metricName
	LabelName               *labelName
	LabelValue              *labelValue
	MetricAndAPPLabelLayout *metricAndAPPLabelLayout
	Target                  *target
	Label                   *label
	MetricLabel             *metricLabel
	MetricTarget            *metricTarget
}

func GetSingleton() *Cache {
	cacheOnce.Do(func() {
		l := &label{}
		t := &target{}
		cacheIns = &Cache{
			canRefresh:              make(chan bool, 1),
			MetricName:              &metricName{},
			LabelName:               &labelName{},
			LabelValue:              &labelValue{},
			MetricAndAPPLabelLayout: &metricAndAPPLabelLayout{},
			Target:                  t,
			Label:                   l,
			MetricLabel:             newMetricLabel(l),
			MetricTarget:            newMetricTarget(t),
		}
	})
	return cacheIns
}

func (t *Cache) Start(ctx context.Context) error {
	if err := t.refresh(false); err != nil {
		return err
	}
	t.canRefresh <- true
	go func() {
		ticker := time.NewTicker(time.Hour)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				select {
				case t.canRefresh <- true:
					t.refresh(false)
				default:
					log.Info("last refresh cache not completed now")
				}
			}
		}
	}()
	return nil
}

func (t *Cache) refresh(fully bool) error {
	log.Info("refresh cache started")
	t.Label.refresh(fully)
	t.Target.refresh(fully)
	eg := &errgroup.Group{}
	AppendErrGroup(eg, t.MetricName.refresh, fully)
	AppendErrGroup(eg, t.LabelName.refresh, fully)
	AppendErrGroup(eg, t.LabelValue.refresh, fully)
	AppendErrGroup(eg, t.MetricAndAPPLabelLayout.refresh, fully)
	AppendErrGroup(eg, t.MetricLabel.refresh, fully)
	AppendErrGroup(eg, t.Target.refresh, fully)
	err := eg.Wait()
	log.Info("refresh cache completed")
	return err

}

func (t *Cache) RefreshFully() error {
	t.Clear()
	err := t.refresh(true)
	return err
}

func (t *Cache) Clear() {
	t.MetricAndAPPLabelLayout.clear()
	t.MetricLabel.clear()
}
