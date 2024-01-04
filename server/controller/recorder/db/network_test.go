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

func newDBNetwork() *mysql.Network {
	return &mysql.Network{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddNetworkBatchSuccess() {
	operator := NewNetwork()
	itemToAdd := newDBNetwork()

	_, ok := operator.AddBatch([]*mysql.Network{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.Network
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Network{})
}

func (t *SuiteTest) TestUpdateNetworkSuccess() {
	operator := NewNetwork()
	addedItem := newDBNetwork()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.Network
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Network{})
}

func (t *SuiteTest) TestDeleteNetworkBatchSuccess() {
	operator := NewNetwork()
	addedItem := newDBNetwork()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.Network
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestNetworkCreateAndFind() {
	lcuuid := uuid.New().String()
	network := &mysql.Network{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(network)
	var resultNetwork *mysql.Network
	err := t.db.Where("lcuuid = ? and name='' and label='' and alias='' and description='' "+
		"and sub_domain='' and region='' and az=''", lcuuid).First(&resultNetwork).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), network.Base.Lcuuid, resultNetwork.Base.Lcuuid)

	resultNetwork = new(mysql.Network)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultNetwork)
	assert.Equal(t.T(), network.Base.Lcuuid, resultNetwork.Base.Lcuuid)

	resultNetwork = new(mysql.Network)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultNetwork)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
