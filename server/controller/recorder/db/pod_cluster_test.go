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

func newDBPodCluster() *mysql.PodCluster {
	return &mysql.PodCluster{Base: mysql.Base{Lcuuid: uuid.New().String()}}
}

func (t *SuiteTest) TestAddPodClusterBatchSuccess() {
	operator := NewPodCluster()
	itemToAdd := newDBPodCluster()

	_, ok := operator.AddBatch([]*mysql.PodCluster{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.PodCluster
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.PodCluster{})
}

func (t *SuiteTest) TestUpdatePodClusterSuccess() {
	operator := NewPodCluster()
	addedItem := newDBPodCluster()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.PodCluster
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.PodCluster{})
}

func (t *SuiteTest) TestDeletePodClusterBatchSuccess() {
	operator := NewPodCluster()
	addedItem := newDBPodCluster()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.PodCluster
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestPodClusterCreateAndFind() {
	lcuuid := uuid.New().String()
	podCluster := &mysql.PodCluster{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(podCluster)
	var resultAZ *mysql.PodCluster
	err := t.db.Where("lcuuid = ? and name='' and cluster_name='' and version='' and az='' "+
		"and region='' and sub_domain=''", lcuuid).First(&resultAZ).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), podCluster.Base.Lcuuid, resultAZ.Base.Lcuuid)

	resultAZ = new(mysql.PodCluster)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultAZ)
	assert.Equal(t.T(), podCluster.Base.Lcuuid, resultAZ.Base.Lcuuid)

	resultAZ = new(mysql.PodCluster)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultAZ)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
