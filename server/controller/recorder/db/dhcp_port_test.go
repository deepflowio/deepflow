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

func newDBDHCPPort() *mysql.DHCPPort {
	return &mysql.DHCPPort{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddDHCPPortBatchSuccess() {
	operator := NewDHCPPort()
	itemToAdd := newDBDHCPPort()

	_, ok := operator.AddBatch([]*mysql.DHCPPort{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.DHCPPort
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.DHCPPort{})
}

func (t *SuiteTest) TestUpdateDHCPPortSuccess() {
	operator := NewDHCPPort()
	addedItem := newDBDHCPPort()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.DHCPPort
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.DHCPPort{})
}

func (t *SuiteTest) TestDeleteDHCPPortBatchSuccess() {
	operator := NewDHCPPort()
	addedItem := newDBDHCPPort()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.DHCPPort
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestDHCPPortCreateAndFind() {
	lcuuid := uuid.New().String()
	dhcPort := &mysql.DHCPPort{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(dhcPort)
	var resultDHCPPort *mysql.DHCPPort
	err := t.db.Where("lcuuid = ? and name='' and az='' and region=''", lcuuid).First(&resultDHCPPort).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), dhcPort.Base.Lcuuid, resultDHCPPort.Base.Lcuuid)

	resultDHCPPort = new(mysql.DHCPPort)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultDHCPPort)
	assert.Equal(t.T(), dhcPort.Base.Lcuuid, resultDHCPPort.Base.Lcuuid)

	resultDHCPPort = new(mysql.DHCPPort)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultDHCPPort)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
