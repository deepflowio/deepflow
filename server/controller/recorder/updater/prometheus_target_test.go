/*
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

package updater

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
)

func (t *SuiteTest) getPrometheusTargetCacheAndCloudItem() (*cache.Cache, cloudmodel.PrometheusTarget) {
	c := cache.NewCache(uuid.New().String())
	c.SetSequence(c.GetSequence() + 1)
	cloudItem := cloudmodel.PrometheusTarget{
		Lcuuid:      uuid.New().String(),
		Job:         "kubernetes-apiservers",
		Instance:    "10.1.18.133:6443",
		ScrapeURL:   "https://10.1.18.133:6443/metrics",
		OtherLabels: "",
	}
	return c, cloudItem
}

func (t *SuiteTest) TestHandleAddPrometheusTargetSuccess() {
	c, cloudItem := t.getPrometheusTargetCacheAndCloudItem()
	updater := NewPrometheusTarget(c, []cloudmodel.PrometheusTarget{cloudItem})
	updater.HandleAddAndUpdate()

	var result *mysql.PrometheusTarget
	dbResult := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&result)
	assert.Equal(t.T(), dbResult.RowsAffected, int64(1))
	assert.Equal(t.T(), cloudItem.Job, result.Job)
	assert.Equal(t.T(), cloudItem.Instance, result.Instance)
	assert.Equal(t.T(), cloudItem.ScrapeURL, result.ScrapeURL)
	assert.Equal(t.T(), cloudItem.OtherLabels, result.OtherLabels)
}

func (t *SuiteTest) TestHandleUpdatePrometheusTargetSuccess() {
	c, cloudItem := t.getPrometheusTargetCacheAndCloudItem()
	updater := NewPrometheusTarget(c, []cloudmodel.PrometheusTarget{cloudItem})
	updater.HandleAddAndUpdate()

	wantInstance := "127.0.0.1:6443"
	wantJob := "prometheus-apiservers"
	wantScrapeURL := "https://127.0.0.1:6443/metrics"
	wantOtherLabels := "app:prometheus"
	cloudItem.Instance, cloudItem.Job, cloudItem.ScrapeURL, cloudItem.OtherLabels = wantInstance, wantJob, wantScrapeURL, wantOtherLabels
	updater.cloudData = []cloudmodel.PrometheusTarget{cloudItem}
	updater.HandleAddAndUpdate()

	var result *mysql.PrometheusTarget
	dbResult := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&result)
	assert.Equal(t.T(), dbResult.RowsAffected, int64(1))
	assert.Equal(t.T(), wantInstance, result.Instance)
	assert.Equal(t.T(), wantJob, result.Job)
	assert.Equal(t.T(), wantScrapeURL, result.ScrapeURL)
	assert.Equal(t.T(), wantOtherLabels, result.OtherLabels)
}

func (t *SuiteTest) TestHandleDeletePrometheusTargetSuccess() {
	c, cloudItem := t.getPrometheusTargetCacheAndCloudItem()
	updater := NewPrometheusTarget(c, []cloudmodel.PrometheusTarget{cloudItem})
	updater.HandleAddAndUpdate()

	updater.cache.SetSequence(updater.cache.GetSequence() + 1)
	updater.HandleDelete()

	var result *mysql.PrometheusTarget
	dbResult := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&result)
	assert.Equal(t.T(), dbResult.RowsAffected, int64(0))
	if updater.cache.DiffBaseDataSet.PrometheusTarget[cloudItem.Lcuuid] != nil {
		t.Errorf(nil, "want cache: nil, actual cache: %+v", updater.cache.DiffBaseDataSet.PrometheusTarget[cloudItem.Lcuuid])
	}
}
