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

package allocator

import (
	"context"
	"sync"
	"time"

	"github.com/op/go-logging"

	"github.com/deepflowio/deepflow/message/controller"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	. "github.com/deepflowio/deepflow/server/controller/side/prometheus/common"
	prometheuscfg "github.com/deepflowio/deepflow/server/controller/side/prometheus/config"
)

var log = logging.MustGetLogger("controller.side.prometheus.allocator")

var (
	alcOnce sync.Once
	alcIns  *Allocator
)

type Allocator struct {
	ctx    context.Context
	cancel context.CancelFunc

	mux     sync.Mutex
	working bool

	IDPoolMap  map[string]idPoolUpdater
	LabelIndex *labelIndex

	RefreshInterval time.Duration
}

func GetSingleton() *Allocator {
	alcOnce.Do(func() {
		alcIns = &Allocator{}
	})
	return alcIns
}

func (m *Allocator) Init(ctx context.Context, cfg *prometheuscfg.Config) {
	log.Infof("init prometheus id mananger")
	mCtx, mCancel := context.WithCancel(ctx)
	m.ctx = mCtx
	m.cancel = mCancel
	m.IDPoolMap = map[string]idPoolUpdater{
		ResourcePrometheusMetricName: newIDPool[mysql.PrometheusMetricName](ResourcePrometheusMetricName, cfg.ResourceMaxID0),
		ResourcePrometheusLabelName:  newIDPool[mysql.PrometheusLabelName](ResourcePrometheusLabelName, cfg.ResourceMaxID0),
		ResourcePrometheusLabelValue: newIDPool[mysql.PrometheusLabelValue](ResourcePrometheusLabelValue, cfg.ResourceMaxID1),
	}
	m.LabelIndex = newLabelIndex()
	m.RefreshInterval = time.Duration(cfg.IDPoolRefreshInterval) * time.Second
	return
}

func (m *Allocator) Start() error {
	m.mux.Lock()
	if m.working {
		return nil
	}
	m.working = true
	m.mux.Unlock()

	log.Info("prometheus allocator started")
	m.refresh()
	go func() {
		ticker := time.NewTicker(m.RefreshInterval)
		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				m.refresh()
			}
		}
	}()
	return nil
}

func (m *Allocator) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.mux.Lock()
	m.working = false
	m.mux.Unlock()
	log.Info("prometheus allocator stopped")
}

func (m *Allocator) refresh() error {
	log.Info("refresh id pools")
	for _, idPool := range m.IDPoolMap {
		err := idPool.refresh()
		if err != nil {
			return err
		}
	}
	log.Info("refresh label index")
	return m.LabelIndex.refresh()
}

func (m *Allocator) AllocateIDs(resourceType string, strs []string) ([]StrID, error) {
	idPool, ok := m.IDPoolMap[resourceType]
	if !ok {
		log.Errorf("resource type (%s) is unsupported", resourceType)
		return []StrID{}, nil
	}
	return idPool.allocate(strs)
}

func (m *Allocator) AllocateLabelIndexes(idxs []*controller.PrometheusAPPLabelIndexRequest) ([]*controller.PrometheusAPPLabelIndexesResponse, error) {
	return m.LabelIndex.allocate(idxs)
}
