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

func newDBRegion() *mysql.Region {
	dbItem := new(mysql.Region)
	dbItem.Lcuuid = uuid.New().String()
	dbItem.Name = uuid.New().String()
	return dbItem
}

func (t *SuiteTest) TestAddRegionBatchSuccess() {
	operator := NewRegion()
	itemToAdd := newDBRegion()

	_, ok := operator.AddBatch([]*mysql.Region{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.Region
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Region{})
}

func (t *SuiteTest) TestUpdateRegionSuccess() {
	operator := NewRegion()
	addedItem := newDBRegion()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.Region
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Region{})
}

func (t *SuiteTest) TestDeleteRegionSuccess() {
	operator := NewRegion()
	addedItem := newDBRegion()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.Region
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestRegionCreateAndFind() {
	lcuuid := uuid.New().String()
	region := &mysql.Region{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(region)
	var resultRegion *mysql.Region
	err := t.db.Where("lcuuid = ? and name='' and label=''", lcuuid).First(&resultRegion).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), region.Base.Lcuuid, resultRegion.Base.Lcuuid)

	resultRegion = new(mysql.Region)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultRegion)
	assert.Equal(t.T(), region.Base.Lcuuid, resultRegion.Base.Lcuuid)

	resultRegion = new(mysql.Region)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultRegion)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
