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

package synchronizer

import (
	"context"
	"sync"
	"time"

	"github.com/op/go-logging"
	"golang.org/x/sync/errgroup"

	"github.com/deepflowio/deepflow/message/controller"
	. "github.com/deepflowio/deepflow/server/controller/side/prometheus/common"
	prometheuscfg "github.com/deepflowio/deepflow/server/controller/side/prometheus/config"
)

var log = logging.MustGetLogger("side.prometheus.synchronizer")

var (
	syncOnce sync.Once
	syncIns  *Synchronizer
)

type Synchronizer struct {
	ctx    context.Context
	cancel context.CancelFunc

	mux             sync.Mutex
	working         bool
	refreshInterval time.Duration

	metricName   *metricName
	labelName    *labelName
	labelValue   *labelValue
	labelLayout  *labelLayout
	label        *label
	metricTarget *metricTarget
}

func GetSingleton() *Synchronizer {
	syncOnce.Do(func() {
		syncIns = &Synchronizer{}
	})
	return syncIns
}

func (m *Synchronizer) Init(ctx context.Context, cfg *prometheuscfg.Config) {
	log.Infof("init prometheus synchronizer")
	mCtx, mCancel := context.WithCancel(ctx)
	m.ctx = mCtx
	m.cancel = mCancel
	m.metricName = newMetricName(cfg.ResourceMaxID0)
	m.labelName = newLabelName(cfg.ResourceMaxID0)
	m.labelValue = newLabelValue(cfg.ResourceMaxID1)
	m.label = newLabel()
	m.labelLayout = newLabelLayout()
	m.metricTarget = newMetricTarget()
	m.refreshInterval = time.Duration(cfg.CacheRefreshInterval) * time.Second
	return
}

func (m *Synchronizer) Start() error {
	m.mux.Lock()
	if m.working {
		return nil
	}
	m.working = true
	m.mux.Unlock()

	log.Info("prometheus synchronizer started")
	m.refresh()
	go func() {
		ticker := time.NewTicker(m.refreshInterval)
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

func (m *Synchronizer) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.mux.Lock()
	m.working = false
	m.mux.Unlock()
	log.Info("prometheus synchronizer stopped")
}

func (m *Synchronizer) refresh() error {
	eg, ctx := errgroup.WithContext(m.ctx)
	AppendErrGroupWithContext(ctx, eg, m.metricName.refresh)
	AppendErrGroupWithContext(ctx, eg, m.labelName.refresh)
	AppendErrGroupWithContext(ctx, eg, m.labelValue.refresh)
	AppendErrGroupWithContext(ctx, eg, m.label.refresh)
	AppendErrGroupWithContext(ctx, eg, m.labelLayout.refresh)
	AppendErrGroupWithContext(ctx, eg, m.metricTarget.refresh)
	return eg.Wait()
}

func (m *Synchronizer) Sync(req *controller.SyncPrometheusRequest) (*controller.SyncPrometheusResponse, error) {
	eg, ctx := errgroup.WithContext(m.ctx)
	resp := new(controller.SyncPrometheusResponse)
	AppendErrGroupWithContext(ctx, eg, m.syncMetricName, resp, req.GetMetricNames())
	AppendErrGroupWithContext(ctx, eg, m.syncLabelName, resp, req.GetLabelNames())
	AppendErrGroupWithContext(ctx, eg, m.syncLabelValue, resp, req.GetLabelValues())
	AppendErrGroupWithContext(ctx, eg, m.syncLabelIndex, resp, req.GetMetricAppLabelLayouts())
	AppendErrGroupWithContext(ctx, eg, m.syncLabel, resp, req.GetLabels())
	AppendErrGroupWithContext(ctx, eg, m.syncMetricTarget, resp, req.GetMetricTargets())
	err := eg.Wait()
	return resp, err
}

func (m *Synchronizer) syncMetricName(args ...interface{}) error {
	resp := args[0].(*controller.SyncPrometheusResponse)
	names := args[1].([]string)
	mns, err := m.metricName.sync(names)
	if err != nil {
		return err
	}
	resp.MetricNames = mns
	return nil
}

func (m *Synchronizer) syncLabelName(args ...interface{}) error {
	resp := args[0].(*controller.SyncPrometheusResponse)
	names := args[1].([]string)
	lns, err := m.labelName.sync(names)
	if err != nil {
		return err
	}
	resp.LabelNames = lns
	return nil
}

func (m *Synchronizer) syncLabelValue(args ...interface{}) error {
	resp := args[0].(*controller.SyncPrometheusResponse)
	values := args[1].([]string)
	lvs, err := m.labelValue.sync(values)
	if err != nil {
		return err
	}
	resp.LabelValues = lvs
	return nil
}

func (m *Synchronizer) syncLabelIndex(args ...interface{}) error {
	resp := args[0].(*controller.SyncPrometheusResponse)
	layouts := args[1].([]*controller.PrometheusMetricAPPLabelLayoutRequest)
	lis, err := m.labelLayout.sync(layouts)
	if err != nil {
		return err
	}
	resp.MetricAppLabelLayouts = lis
	return nil
}

func (m *Synchronizer) syncLabel(args ...interface{}) error {
	resp := args[0].(*controller.SyncPrometheusResponse)
	labels := args[1].([]*controller.PrometheusLabel)
	err := m.label.sync(labels)
	if err != nil {
		return err
	}
	resp.Labels = labels
	return nil
}

func (m *Synchronizer) syncMetricTarget(args ...interface{}) error {
	resp := args[0].(*controller.SyncPrometheusResponse)
	targets := args[1].([]*controller.PrometheusMetricTarget)
	err := m.metricTarget.sync(targets)
	if err != nil {
		return err
	}
	resp.MetricTargets = targets
	return nil
}
