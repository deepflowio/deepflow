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

	metadbmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

func newDBCEN() *metadbmodel.CEN {
	return &metadbmodel.CEN{Base: metadbmodel.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddCENBatchSuccess() {
	operator := NewCEN()
	itemToAdd := newDBCEN()

	_, ok := operator.AddBatch([]*metadbmodel.CEN{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *metadbmodel.CEN
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&metadbmodel.CEN{})
}

func (t *SuiteTest) TestUpdateCENSuccess() {
	operator := NewCEN()
	addedItem := newDBCEN()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *metadbmodel.CEN
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&metadbmodel.CEN{})
}

func (t *SuiteTest) TestDeleteCENBatchSuccess() {
	operator := NewCEN()
	addedItem := newDBCEN()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *metadbmodel.CEN
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestCENCreateAndFind() {
	lcuuid := uuid.New().String()
	cen := &metadbmodel.CEN{
		Base: metadbmodel.Base{Lcuuid: lcuuid},
	}
	t.db.Create(cen)
	var resultCEN *metadbmodel.CEN
	err := t.db.Where("lcuuid = ? and name='' and label='' and alias='' and epc_ids=''", lcuuid).First(&resultCEN).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), cen.Base.Lcuuid, resultCEN.Base.Lcuuid)

	resultCEN = new(metadbmodel.CEN)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultCEN)
	assert.Equal(t.T(), cen.Base.Lcuuid, resultCEN.Base.Lcuuid)

	resultCEN = new(metadbmodel.CEN)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultCEN)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
