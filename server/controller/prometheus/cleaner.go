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
	"errors"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	prometheuscfg "github.com/deepflowio/deepflow/server/controller/prometheus/config"
	"github.com/deepflowio/deepflow/server/controller/prometheus/encoder"
)

var (
	cleanerOnce sync.Once
	cleaner     *Cleaner
)

const (
	labelNameInstance = "instance"
	labelNameJob      = "job"
)

type Cleaner struct {
	ctx    context.Context
	cancel context.CancelFunc

	canClean chan struct{}
	interval time.Duration

	encoder *encoder.Encoder
}

func GetCleaner() *Cleaner {
	cleanerOnce.Do(func() {
		en, _ := encoder.GetEncoder(1)
		cleaner = &Cleaner{
			encoder:  en,
			canClean: make(chan struct{}, 1),
		}
	})
	return cleaner
}

func (c *Cleaner) Init(ctx context.Context, cfg *prometheuscfg.Config) {
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.interval = time.Duration(cfg.DataCleanInterval) * time.Minute
	c.canClean <- struct{}{}
}

func (c *Cleaner) Start() error {
	log.Info("prometheus data cleaner started")
	go func() {
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.clear(time.Time{})
			}
		}
	}()
	return nil
}

func (c *Cleaner) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	log.Info("prometheus data cleaner stopped")
}

func (c *Cleaner) Clear(expiredAt time.Time) error {
	log.Infof("prometheus data cleaner clear by hand")
	return c.clear(expiredAt)
}

func (c *Cleaner) clear(expiredAt time.Time) error {
	select {
	case <-c.canClean:
		log.Info("prometheus data cleaner clear started")
		if err := c.deleteExpired(expiredAt); err == nil {
			c.encoder.Refresh()
		}
		log.Info("prometheus data cleaner clear completed")
		c.canClean <- struct{}{}
		return nil
	default:
		log.Info("prometheus data cleaner clear skipped")
		return errors.New("cleaner is busy, try again later")
	}
}

// total retention time is data_source retention hours (get from db) + 24 hours
func (c *Cleaner) getExpiredTime() time.Time {
	var dataSource *mysql.DataSource
	mysql.Db.Where("display_name = ?", "Prometheus 数据").Find(&dataSource)
	dataSourceRetentionHours := 7 * 24
	if dataSource != nil {
		dataSourceRetentionHours = dataSource.RetentionTime
	}
	return time.Now().Add(time.Duration(-(dataSourceRetentionHours + 24)) * time.Hour)
}

func (c *Cleaner) getTargetInstanceJobValues() (values []string) {
	var targets []mysql.PrometheusTarget
	mysql.Db.Select("instance, job").Find(&targets)
	for _, target := range targets {
		values = append(values, target.Instance)
		values = append(values, target.Job)
	}
	return
}

func (c *Cleaner) deleteExpired(expiredAt time.Time) error {
	if expiredAt.IsZero() {
		expiredAt = c.getExpiredTime()
	}
	log.Infof("clear expired data (synced_at < %s) started", expiredAt.Format(common.GO_BIRTHDAY))

	count := 0
	for {
		if count > 3 {
			break
		}
		if err := c.tryDeleteExpired(expiredAt); err == nil {
			break
		}
		count++
		time.Sleep(10 * time.Second)
	}
	log.Info("clear expired data completed")
	return nil
}

func (c *Cleaner) tryDeleteExpired(expiredAt time.Time) error {
	var e error
	if err := c.deleteExpiredMetricLabelName(expiredAt); err != nil {
		log.Errorf("mysql delete failed: %v", err)
		e = err
	}
	if err := c.deleteExpiredMetricAPPLabelLayout(expiredAt); err != nil {
		log.Errorf("mysql delete failed: %v", err)
		e = err
	}
	if err := c.deleteExpiredMetricName(expiredAt); err != nil {
		log.Errorf("mysql delete failed: %v", err)
		e = err
	}
	if err := c.deleteExpiredLabel(expiredAt); err != nil {
		log.Errorf("mysql delete failed: %v", err)
		e = err
	}
	if err := c.deleteExpiredLabelName(expiredAt); err != nil {
		log.Errorf("mysql delete failed: %v", err)
		e = err
	}
	if err := c.deleteExpiredLabelValue(expiredAt); err != nil {
		log.Errorf("mysql delete failed: %v", err)
		e = err
	}
	return e
}

func (c *Cleaner) deleteExpiredMetricName(expiredAt time.Time) error {
	metricNames, err := DeleteExpired[mysql.PrometheusMetricName](mysql.Db, expiredAt, "metric_name")
	if err != nil {
		return err
	}
	mns := make([]string, 0)
	for _, metricName := range metricNames {
		mns = append(mns, metricName.Name)
	}
	if len(mns) > 0 {
		var metricLabelNames []mysql.PrometheusMetricLabelName
		var appLabels []mysql.PrometheusMetricAPPLabelLayout
		var metricTargets []mysql.PrometheusMetricTarget
		if err := mysql.Db.Where("metric_name IN (?)", mns).Delete(&metricLabelNames).Error; err != nil {
			return err
		}
		if err := mysql.Db.Where("metric_name IN (?)", mns).Delete(&appLabels).Error; err != nil {
			return err
		}
		if err := mysql.Db.Where("metric_name IN (?)", mns).Delete(&metricTargets).Error; err != nil {
			return err
		}
	}
	return nil
}

func (c *Cleaner) deleteExpiredLabel(expiredAt time.Time) error {
	_, err := DeleteExpired[mysql.PrometheusLabel](mysql.Db.Where("name NOT IN (?)", []string{labelNameInstance, labelNameJob}), expiredAt, "label")
	return err
}

func (c *Cleaner) deleteExpiredLabelName(expiredAt time.Time) error {
	labelNames, err := DeleteExpired[mysql.PrometheusLabelName](mysql.Db.Where("name NOT IN (?)", []string{labelNameInstance, labelNameJob}), expiredAt, "label_name")
	if err != nil {
		return err
	}
	lns := make([]string, 0)
	lnIDs := make([]int, 0)
	for _, labelName := range labelNames {
		lns = append(lns, labelName.Name)
		lnIDs = append(lnIDs, labelName.ID)
	}
	if len(lns) > 0 {
		var labels []mysql.PrometheusLabel
		var appLabels []mysql.PrometheusMetricAPPLabelLayout
		if err := mysql.Db.Where("name IN (?)", lns).Delete(&labels).Error; err != nil {
			return err
		}
		if err := mysql.Db.Where("app_label_name IN (?)", lns).Delete(&appLabels).Error; err != nil {
			return err
		}

		var metricLabelNames []mysql.PrometheusMetricLabelName
		if err := mysql.Db.Where("label_name_id IN (?)", lnIDs).Delete(&metricLabelNames).Error; err != nil {
			return err
		}
	}
	return nil
}

func (c *Cleaner) deleteExpiredLabelValue(expiredAt time.Time) error {
	instancesJobValues := c.getTargetInstanceJobValues()
	labelValues, err := DeleteExpired[mysql.PrometheusLabelValue](mysql.Db.Where("value NOT IN (?)", instancesJobValues), expiredAt, "label_value")
	if err != nil {
		return err
	}
	lvs := make([]string, 0)
	for _, labelValue := range labelValues {
		lvs = append(lvs, labelValue.Value)
	}
	if len(lvs) > 0 {
		var labels []mysql.PrometheusLabel
		if err := mysql.Db.Where("value IN (?)", lvs).Delete(&labels).Error; err != nil {
			return err
		}
	}
	return nil
}

func (c *Cleaner) deleteExpiredMetricLabelName(expiredAt time.Time) error {
	_, err := DeleteExpired[mysql.PrometheusMetricLabelName](mysql.Db, expiredAt, "metric_label_name")
	if err != nil {
		return err
	}
	return nil
}

func (c *Cleaner) deleteExpiredMetricAPPLabelLayout(expiredAt time.Time) error {
	_, err := DeleteExpired[mysql.PrometheusMetricAPPLabelLayout](mysql.Db, expiredAt, "metric_app_label_layout")
	if err != nil {
		return err
	}
	return nil
}

func DeleteExpired[MT any](query *gorm.DB, expiredAt time.Time, resourceType string) ([]MT, error) {
	var items []MT
	if err := query.Where("synced_at < ?", expiredAt).Find(&items).Error; err != nil {
		log.Errorf("mysql delete resource failed: %v", err)
		return items, err
	}
	if len(items) == 0 {
		return items, nil
	}

	count := len(items)
	offset := 5000
	pages := count/offset + 1
	if count%offset == 0 {
		pages = count / offset
	}
	for i := 0; i < pages; i++ {
		start := i * offset
		end := (i + 1) * offset
		if end > count {
			end = count
		}
		toDel := items[start:end]
		if err := mysql.Db.Delete(&toDel).Error; err != nil {
			log.Errorf("mysql delete %s failed: %v", resourceType, err)
			return items, err
		}
		log.Infof("clear %s data count: %d", resourceType, len(toDel))
		log.Debugf("clear %s data detail: %v", resourceType, items)
	}

	return items, nil
}
