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

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	prometheuscfg "github.com/deepflowio/deepflow/server/controller/prometheus/config"
)

var (
	cleanerOnce sync.Once
	cleaner     *Cleaner
)

type Cleaner struct {
	ctx    context.Context
	cancel context.CancelFunc

	mux      sync.Mutex
	working  bool
	interval time.Duration
}

func GetCleaner() *Cleaner {
	cleanerOnce.Do(func() {
		cleaner = &Cleaner{}
	})
	return cleaner
}

func (c *Cleaner) Init(ctx context.Context, cfg *prometheuscfg.Config) {
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.interval = time.Duration(cfg.DataCleanInterval) * time.Hour
}

func (c *Cleaner) Start() error {
	c.mux.Lock()
	if c.working {
		c.mux.Unlock()
		return nil
	}
	c.working = true
	c.mux.Unlock()

	log.Info("prometheus data cleaner started")
	c.clean()
	go func() {
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.clean()
			}
		}
	}()
	return nil
}

func (c *Cleaner) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.mux.Lock()
	c.working = false
	c.mux.Unlock()
	log.Info("prometheus data cleaner stopped")
}

func (c *Cleaner) clean() {
	log.Info("prometheus data cleaner clean started")
	c.deleteExpired()
	c.deleteDirty()
	log.Info("prometheus data cleaner clean stopped")
}

func (c *Cleaner) deleteExpired() {
	var dataSource *mysql.DataSource
	mysql.Db.Where("display_name = ?", "Prometheus 数据").Find(&dataSource)
	dataSourceRetentionHours := 7 * 24
	if dataSource != nil {
		dataSourceRetentionHours = dataSource.RetentionTime
	}
	// total retention time is data_source retention hours (get from db) + 24 hours
	expiredAt := time.Now().Add(time.Duration(-(dataSourceRetentionHours + 24)) * time.Hour)
	log.Infof("clean data (synced_at < %s) started", expiredAt.Format(common.GO_BIRTHDAY))
	DeleteExpired[mysql.PrometheusMetricName](expiredAt)
	DeleteExpired[mysql.PrometheusMetricLabel](expiredAt)
	DeleteExpired[mysql.PrometheusMetricAPPLabelLayout](expiredAt)
	DeleteExpired[mysql.PrometheusLabel](expiredAt)
	DeleteExpired[mysql.PrometheusLabelName](expiredAt)
	DeleteExpired[mysql.PrometheusLabelValue](expiredAt)
	log.Info("clean data completed")
}

func DeleteExpired[MT any](expiredAt time.Time) {
	err := mysql.Db.Where("synced_at < ?", expiredAt).Delete(new(MT)).Error
	if err != nil {
		log.Errorf("mysql delete resource failed: %v", err)
	}
}

func (c *Cleaner) deleteDirty() {
	var labelNames []*mysql.PrometheusLabelName
	mysql.Db.Find(&labelNames)
	lns := make([]string, 0)
	for _, labelName := range labelNames {
		lns = append(lns, labelName.Name)
	}
	if len(lns) > 0 {
		mysql.Db.Where("name NOT IN (?)", lns).Delete(&mysql.PrometheusLabel{})
		mysql.Db.Where("app_label_name NOT IN (?)", lns).Delete(&mysql.PrometheusMetricAPPLabelLayout{})
	}

	var labelValues []*mysql.PrometheusLabelValue
	mysql.Db.Find(&labelValues)
	lvs := make([]string, 0)
	for _, labelValue := range labelValues {
		lvs = append(lvs, labelValue.Value)
	}
	if len(lvs) > 0 {
		mysql.Db.Where("value NOT IN (?)", lvs).Delete(&mysql.PrometheusLabel{})
	}

	var labels []*mysql.PrometheusLabel
	mysql.Db.Find(&labels)
	lis := make([]int, 0)
	for _, label := range labels {
		lis = append(lis, label.ID)
	}
	if len(lis) > 0 {
		mysql.Db.Where("label_id NOT IN (?)", lis).Delete(&mysql.PrometheusMetricLabel{})
	}

	var metricNames []*mysql.PrometheusMetricName
	mysql.Db.Find(&metricNames)
	mns := make([]string, 0)
	for _, metricName := range metricNames {
		mns = append(mns, metricName.Name)
	}
	if len(mns) > 0 {
		mysql.Db.Where("metric_name NOT IN (?)", mns).Delete(&mysql.PrometheusMetricLabel{})
		mysql.Db.Where("metric_name NOT IN (?)", mns).Delete(&mysql.PrometheusMetricAPPLabelLayout{})
		mysql.Db.Where("metric_name NOT IN (?)", mns).Delete(&mysql.PrometheusMetricTarget{})
	}
}
