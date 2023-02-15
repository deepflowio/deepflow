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

func newDBHost() *mysql.Host {
	return &mysql.Host{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddHostBatchSuccess() {
	operator := NewHost()
	itemToAdd := newDBHost()

	_, ok := operator.AddBatch([]*mysql.Host{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.Host
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Host{})
}

func (t *SuiteTest) TestUpdateHostSuccess() {
	operator := NewHost()
	addedItem := newDBHost()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.Host
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Host{})
}

func (t *SuiteTest) TestDeleteHostSuccess() {
	operator := NewHost()
	addedItem := newDBHost()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.Host
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestHostCreateAndFind() {
	lcuuid := uuid.New().String()
	host := &mysql.Host{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(host)
	var resultHost *mysql.Host
	err := t.db.Where("lcuuid = ? and name='' and alias='' and description='' and ip='' and user_name='' "+
		"and user_passwd='' and az='' and region='' and domain=''", lcuuid).First(&resultHost).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), host.Base.Lcuuid, resultHost.Base.Lcuuid)

	resultHost = new(mysql.Host)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultHost)
	assert.Equal(t.T(), host.Base.Lcuuid, resultHost.Base.Lcuuid)

	resultHost = new(mysql.Host)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultHost)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
