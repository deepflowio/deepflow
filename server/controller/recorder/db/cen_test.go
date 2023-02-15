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

func newDBCEN() *mysql.CEN {
	return &mysql.CEN{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddCENBatchSuccess() {
	operator := NewCEN()
	itemToAdd := newDBCEN()

	_, ok := operator.AddBatch([]*mysql.CEN{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.CEN
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.CEN{})
}

func (t *SuiteTest) TestUpdateCENSuccess() {
	operator := NewCEN()
	addedItem := newDBCEN()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.CEN
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.CEN{})
}

func (t *SuiteTest) TestDeleteCENBatchSuccess() {
	operator := NewCEN()
	addedItem := newDBCEN()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.CEN
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestCENCreateAndFind() {
	lcuuid := uuid.New().String()
	cen := &mysql.CEN{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(cen)
	var resultCEN *mysql.CEN
	err := t.db.Where("lcuuid = ? and name='' and label='' and alias='' and epc_ids=''", lcuuid).First(&resultCEN).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), cen.Base.Lcuuid, resultCEN.Base.Lcuuid)

	resultCEN = new(mysql.CEN)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultCEN)
	assert.Equal(t.T(), cen.Base.Lcuuid, resultCEN.Base.Lcuuid)

	resultCEN = new(mysql.CEN)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultCEN)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
