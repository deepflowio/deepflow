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

package prometheus

import (
	"context"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/prometheus/cache"
	"github.com/deepflowio/deepflow/server/controller/prometheus/common"
	prometheuscfg "github.com/deepflowio/deepflow/server/controller/prometheus/config"
	"github.com/deepflowio/deepflow/server/controller/prometheus/encoder"
)

var (
	appLabelLayoutUpdaterOnce sync.Once
	appLabelLayoutUpdater     *APPLabelLayoutUpdater
)

// APPLabelLayoutUpdater update prometheus_metric_app_label_layout encoder cache, because label type can be changed by target info from recorder
type APPLabelLayoutUpdater struct {
	ctx    context.Context
	cancel context.CancelFunc

	refreshInterval time.Duration

	encoder *encoder.Encoder
}

func GetAPPLabelLayoutUpdater() *APPLabelLayoutUpdater {
	appLabelLayoutUpdaterOnce.Do(func() {
		appLabelLayoutUpdater = &APPLabelLayoutUpdater{
			encoder: encoder.GetSingleton(),
		}
	})
	return appLabelLayoutUpdater
}

func (au *APPLabelLayoutUpdater) Init(ctx context.Context, cfg *prometheuscfg.Config) {
	au.ctx, au.cancel = context.WithCancel(ctx)
	au.refreshInterval = time.Duration(cfg.SynchronizerCacheRefreshInterval) * time.Second
}

func (e *APPLabelLayoutUpdater) Start() error {
	log.Info("prometheus app label layout updater started")
	go func() {
		ticker := time.NewTicker(e.refreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-e.ctx.Done():
				return
			case <-ticker.C:
				e.refresh()
			}
		}
	}()
	return nil
}

func (au *APPLabelLayoutUpdater) Stop() {
	if au.cancel != nil {
		au.cancel()
	}
	log.Info("prometheus app label layout updater stopped")
}

func (au *APPLabelLayoutUpdater) refresh() error {
	log.Info("prometheus app label layout refresh started")
	td := newToolDataSet()
	err := td.load()
	if err != nil {
		return err
	}

	for mn, lns := range td.metricNameToLabelNames {
		newAPPLabelNames := lns.Difference(mapset.NewSet([]string{common.TargetLabelInstance, common.TargetLabelJob}...))
		if targetLNs, ok := td.metricNameToTargetLabelNames[mn]; ok {
			newAPPLabelNames = newAPPLabelNames.Difference(targetLNs)
		}
		oldAPPLabelNames, ok := td.metricNameToAPPLabelNames[mn]
		if !ok {
			oldAPPLabelNames = mapset.NewSet[string]()
		}

		if appLabelNamesToEncode := newAPPLabelNames.Difference(oldAPPLabelNames).ToSlice(); len(appLabelNamesToEncode) > 0 {
			_, err = au.encoder.LabelLayout.SingleEncode(mn, appLabelNamesToEncode)
			if err != nil {
				log.Infof("encode metric: %s labels: %v failed: %s", mn, appLabelNamesToEncode, err.Error())
			}
		}

		indexesToRecycle := make([]int, 0)
		for _, item := range oldAPPLabelNames.Difference(newAPPLabelNames).ToSlice() {
			if idx, ok := td.layoutKeyToIndex[cache.NewLayoutKey(mn, item)]; ok {
				indexesToRecycle = append(indexesToRecycle, int(idx))
			}
		}
		if len(indexesToRecycle) > 0 {
			err = au.encoder.LabelLayout.SingleRelease(mn, indexesToRecycle)
			if err != nil {
				log.Infof("recycle metric: %s label indexes: %v failed: %s", mn, indexesToRecycle, err.Error())
			}
		}
	}
	log.Info("prometheus app label layout refresh completed")
	return err
}

type toolData struct {
	cache *cache.Cache

	metricNameToLabelNames       map[string]mapset.Set[string]
	metricNameToTargetLabelNames map[string]mapset.Set[string]
	metricNameToAPPLabelNames    map[string]mapset.Set[string]
	layoutKeyToIndex             map[cache.LayoutKey]uint8
}

func newToolDataSet() *toolData {
	return &toolData{
		cache: cache.GetSingleton(),

		metricNameToLabelNames:       make(map[string]mapset.Set[string]),
		metricNameToTargetLabelNames: make(map[string]mapset.Set[string]),
		metricNameToAPPLabelNames:    make(map[string]mapset.Set[string]),
		layoutKeyToIndex:             make(map[cache.LayoutKey]uint8),
	}
}

func (td *toolData) load() error {
	metricNameToTargetIDs := td.cache.MetricTarget.GetMetricNameToTargetIDs()
	targetIDToLabelNames := td.cache.Target.GetTargetIDToLabelNames()
	for mn, tids := range metricNameToTargetIDs {
		for _, tid := range tids.ToSlice() {
			lns, ok := targetIDToLabelNames[tid]
			if !ok {
				continue
			}
			if _, ok := td.metricNameToTargetLabelNames[mn]; !ok {
				td.metricNameToTargetLabelNames[mn] = mapset.NewSet[string]()
			}
			td.metricNameToTargetLabelNames[mn] = td.metricNameToTargetLabelNames[mn].Union(lns)
		}
	}

	var layouts []*mysql.PrometheusMetricAPPLabelLayout
	err := mysql.Db.Find(&layouts).Error
	if err != nil {
		return err
	}
	for _, item := range layouts {
		if _, ok := td.metricNameToAPPLabelNames[item.MetricName]; !ok {
			td.metricNameToAPPLabelNames[item.MetricName] = mapset.NewSet[string]()
		}
		td.metricNameToAPPLabelNames[item.MetricName].Add(item.APPLabelName)
		td.layoutKeyToIndex[cache.NewLayoutKey(item.MetricName, item.APPLabelName)] = item.APPLabelColumnIndex
	}

	td.cache.MetricLabelName.GetMetricNameIDToLabelNameIDs().Range(func(mni int, lis mapset.Set[int]) bool {
		if mn, ok := td.cache.MetricName.GetNameByID(mni); ok {
			for _, li := range lis.ToSlice() {
				if ln, ok := td.cache.LabelName.GetNameByID(li); ok {
					if _, ok := td.metricNameToLabelNames[mn]; !ok {
						td.metricNameToLabelNames[mn] = mapset.NewSet[string]()
					}
					td.metricNameToLabelNames[mn].Add(ln)
				}
			}
		}
		return true
	})
	return nil
}
