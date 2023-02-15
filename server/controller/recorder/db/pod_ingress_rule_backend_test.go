/*
 * Copyright (c) 2022 Yunshan Networks
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

func newDBPodIngressRuleBackend() *mysql.PodIngressRuleBackend {
	return &mysql.PodIngressRuleBackend{Base: mysql.Base{Lcuuid: uuid.New().String()}}
}

func (t *SuiteTest) TestAddPodIngressRuleBackendBatchSuccess() {
	operator := NewPodIngressRuleBackend()
	itemToAdd := newDBPodIngressRuleBackend()

	_, ok := operator.AddBatch([]*mysql.PodIngressRuleBackend{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.PodIngressRuleBackend
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.PodIngressRuleBackend{})
}

func (t *SuiteTest) TestDeletePodIngressRuleBackendBatchSuccess() {
	operator := NewPodIngressRuleBackend()
	addedItem := newDBPodIngressRuleBackend()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.PodIngressRuleBackend
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
