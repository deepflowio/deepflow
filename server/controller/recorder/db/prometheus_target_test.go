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

package db

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func newDBPrometheusTarget() *mysql.PrometheusTarget {
	return &mysql.PrometheusTarget{
		Base:        mysql.Base{Lcuuid: uuid.New().String()},
		Job:         "kubernetes-apiservers",
		Instance:    "10.1.18.133:6443",
		ScrapeURL:   "https://10.1.18.133:6443/metrics",
		OtherLabels: "",
	}
}

func (t *SuiteTest) TestAddPrometheusTargetBatchSuccess() {
	operator := NewPrometheusTarget()
	itemToAdd := newDBPrometheusTarget()

	_, ok := operator.AddBatch([]*mysql.PrometheusTarget{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.PrometheusTarget
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.PrometheusTarget{})
}

func (t *SuiteTest) TestUpdatePrometheusTargetSuccess() {
	operator := NewPrometheusTarget()
	addedItem := newDBPrometheusTarget()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"job": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.PrometheusTarget
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Job, updateInfo["job"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.PrometheusTarget{})
}

func (t *SuiteTest) TestDeletePrometheusTargetBatchSuccess() {
	operator := NewPrometheusTarget()
	addedItem := newDBPrometheusTarget()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.PrometheusTarget
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestPrometheusTargetCreateAndFind() {
	lcuuid := uuid.New().String()
	prometheusTarget := &mysql.PrometheusTarget{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(prometheusTarget)
	var resultPrometheusTarget *mysql.PrometheusTarget
	err := t.db.Where("lcuuid = ? and job='' and instance='' and scrape_url='' and other_labels='' and sub_domain=''", lcuuid).First(&resultPrometheusTarget).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), prometheusTarget.Base.Lcuuid, resultPrometheusTarget.Base.Lcuuid)

	resultPrometheusTarget = new(mysql.PrometheusTarget)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultPrometheusTarget)
	assert.Equal(t.T(), prometheusTarget.Base.Lcuuid, resultPrometheusTarget.Base.Lcuuid)

	resultPrometheusTarget = new(mysql.PrometheusTarget)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultPrometheusTarget)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
