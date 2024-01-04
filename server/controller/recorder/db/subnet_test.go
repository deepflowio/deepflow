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

func newDBSubnet() *mysql.Subnet {
	return &mysql.Subnet{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddSubnetBatchSuccess() {
	operator := NewSubnet()
	itemToAdd := newDBSubnet()

	_, ok := operator.AddBatch([]*mysql.Subnet{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.Subnet
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Subnet{})
}

func (t *SuiteTest) TestUpdateSubnetSuccess() {
	operator := NewSubnet()
	addedItem := newDBSubnet()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.Subnet
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Subnet{})
}

func (t *SuiteTest) TestDeleteSubnetBatchSuccess() {
	operator := NewSubnet()
	addedItem := newDBSubnet()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.Subnet
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestSubnetCreateAndFind() {
	lcuuid := uuid.New().String()
	subnet := &mysql.Subnet{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(subnet)
	var resultSubnet *mysql.Subnet
	err := t.db.Where("lcuuid = ? and name='' and label='' and prefix='' and netmask=''", lcuuid).First(&resultSubnet).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), subnet.Base.Lcuuid, resultSubnet.Base.Lcuuid)

	resultSubnet = new(mysql.Subnet)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultSubnet)
	assert.Equal(t.T(), subnet.Base.Lcuuid, resultSubnet.Base.Lcuuid)

	resultSubnet = new(mysql.Subnet)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultSubnet)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
