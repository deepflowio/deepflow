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

func newDBVInterface() *mysql.VInterface {
	return &mysql.VInterface{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String(), Region: uuid.New().String()}
}

func (t *SuiteTest) TestAddVInterfaceBatchSuccess() {
	operator := NewVInterface()
	itemToAdd := newDBVInterface()

	_, ok := operator.AddBatch([]*mysql.VInterface{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.VInterface
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VInterface{})
}

func (t *SuiteTest) TestUpdateVInterfaceSuccess() {
	operator := NewVInterface()
	addedItem := newDBVInterface()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"region": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.VInterface
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Region, updateInfo["region"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VInterface{})
}

func (t *SuiteTest) TestDeleteVInterfaceBatchSuccess() {
	operator := NewVInterface()
	addedItem := newDBVInterface()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.VInterface
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestVInterfaceCreateAndFind() {
	lcuuid := uuid.New().String()
	vInterface := &mysql.VInterface{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(vInterface)
	var resultVInterface *mysql.VInterface
	err := t.db.Where("lcuuid = ? and name='' and mac='' and tap_mac='' and "+
		"sub_domain='' and region=''", lcuuid).First(&resultVInterface).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), vInterface.Base.Lcuuid, resultVInterface.Base.Lcuuid)

	resultVInterface = new(mysql.VInterface)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultVInterface)
	assert.Equal(t.T(), vInterface.Base.Lcuuid, resultVInterface.Base.Lcuuid)

	resultVInterface = new(mysql.VInterface)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultVInterface)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
