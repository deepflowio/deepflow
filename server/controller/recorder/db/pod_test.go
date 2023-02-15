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

func newDBPod() *mysql.Pod {
	return &mysql.Pod{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddPodBatchSuccess() {
	operator := NewPod()
	itemToAdd := newDBPod()

	_, ok := operator.AddBatch([]*mysql.Pod{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.Pod
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Pod{})
}

func (t *SuiteTest) TestUpdatePodSuccess() {
	operator := NewPod()
	addedItem := newDBPod()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.Pod
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Pod{})
}

func (t *SuiteTest) TestDeletePodBatchSuccess() {
	operator := NewPod()
	addedItem := newDBPod()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.Pod
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestPodCreateAndFind() {
	lcuuid := uuid.New().String()
	pod := &mysql.Pod{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(pod)
	var resultPod *mysql.Pod
	err := t.db.Where("lcuuid = ? and name='' and alias='' and label='' and az='' and "+
		"region='' and sub_domain=''", lcuuid).First(&resultPod).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), pod.Base.Lcuuid, resultPod.Base.Lcuuid)

	resultPod = new(mysql.Pod)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultPod)
	assert.Equal(t.T(), pod.Base.Lcuuid, resultPod.Base.Lcuuid)

	resultPod = new(mysql.Pod)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultPod)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
