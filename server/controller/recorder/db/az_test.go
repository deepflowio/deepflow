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

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func newDBAZ() *mysql.AZ {
	dbItem := new(mysql.AZ)
	dbItem.Lcuuid = uuid.New().String()
	dbItem.Name = uuid.New().String()
	return dbItem
}

func (t *SuiteTest) TestAddAZBatchSuccess() {
	operator := NewAZ()
	itemToAdd := newDBAZ()

	_, ok := operator.AddBatch([]*mysql.AZ{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.AZ
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)

	clearDBData[mysql.AZ](t.db)
}

func (t *SuiteTest) TestAddAZBatchWithDupLcuuidSuccess() {
	operator := NewAZ()
	itemToAdd := newDBAZ()
	lcuuid := itemToAdd.Lcuuid
	itemToAdd.ID = 10
	result := t.db.Create(&itemToAdd)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	t.db.Delete(&itemToAdd)

	itemToAdd = newDBAZ()
	itemToAdd.ID = 0
	itemToAdd.Lcuuid = lcuuid
	_, ok := operator.AddBatch([]*mysql.AZ{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.AZ
	result = t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)
	assert.Equal(t.T(), addedItem.ID, 10)

	clearDBData[mysql.AZ](t.db)
}

func (t *SuiteTest) TestUpdateAZSuccess() {
	operator := NewAZ()
	addedItem := newDBAZ()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.AZ
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	clearDBData[mysql.AZ](t.db)
}

func (t *SuiteTest) TestDeleteAZSuccess() {
	operator := NewAZ()
	addedItem := newDBAZ()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.AZ
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))

	clearDBData[mysql.AZ](t.db)
}

func (t *SuiteTest) TestAZCreateAndFind() {
	lcuuid := uuid.New().String()
	az := &mysql.AZ{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(az)
	var resultAZ *mysql.AZ
	err := t.db.Where("lcuuid = ? and name='' and label='' and region='' and domain=''", lcuuid).First(&resultAZ).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), az.Base.Lcuuid, resultAZ.Base.Lcuuid)

	resultAZ = new(mysql.AZ)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultAZ)
	assert.Equal(t.T(), az.Base.Lcuuid, resultAZ.Base.Lcuuid)

	resultAZ = new(mysql.AZ)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultAZ)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
