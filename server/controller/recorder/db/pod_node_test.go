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

func newDBPodNode() *mysql.PodNode {
	return &mysql.PodNode{Base: mysql.Base{Lcuuid: uuid.New().String()}, Region: uuid.New().String()}
}

func (t *SuiteTest) TestAddPodNodeBatchSuccess() {
	operator := NewPodNode()
	itemToAdd := newDBPodNode()

	_, ok := operator.AddBatch([]*mysql.PodNode{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.PodNode
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.PodNode{})
}

func (t *SuiteTest) TestUpdatePodNodeSuccess() {
	operator := NewPodNode()
	addedItem := newDBPodNode()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"region": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.PodNode
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Region, updateInfo["region"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.PodNode{})
}

func (t *SuiteTest) TestDeletePodNodeBatchSuccess() {
	operator := NewPodNode()
	addedItem := newDBPodNode()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.PodNode
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestPodNodeCreateAndFind() {
	lcuuid := uuid.New().String()
	pd := &mysql.PodNode{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(pd)
	var resultPodNode *mysql.PodNode
	err := t.db.Where("lcuuid = ? and name='' and alias='' and ip='' and region='' and sub_domain='' and az=''", lcuuid).First(&resultPodNode).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), pd.Base.Lcuuid, resultPodNode.Base.Lcuuid)

	resultPodNode = new(mysql.PodNode)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultPodNode)
	assert.Equal(t.T(), pd.Base.Lcuuid, resultPodNode.Base.Lcuuid)

	resultPodNode = new(mysql.PodNode)
	result := t.db.Where("lcuuid = ? and alias = null", lcuuid).Find(&resultPodNode)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
