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

func newDBFloatingIP() *mysql.FloatingIP {
	return &mysql.FloatingIP{Base: mysql.Base{Lcuuid: uuid.New().String()}, IP: uuid.New().String(), Region: uuid.New().String()}
}

func (t *SuiteTest) TestAddFloatingIPBatchSuccess() {
	operator := NewFloatingIP()
	itemToAdd := newDBFloatingIP()

	_, ok := operator.AddBatch([]*mysql.FloatingIP{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.FloatingIP
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.IP, itemToAdd.IP)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.FloatingIP{})
}

func (t *SuiteTest) TestUpdateFloatingIPSuccess() {
	operator := NewFloatingIP()
	addedItem := newDBFloatingIP()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"region": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.FloatingIP
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Region, updateInfo["region"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.FloatingIP{})
}

func (t *SuiteTest) TestDeleteFloatingIPBatchSuccess() {
	operator := NewFloatingIP()
	addedItem := newDBFloatingIP()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.FloatingIP
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestFloatingIPCreateAndFind() {
	lcuuid := uuid.New().String()
	floatingIP := &mysql.FloatingIP{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(floatingIP)
	var resultFloatingIP *mysql.FloatingIP
	err := t.db.Where("lcuuid = ? and ip='' and region='' and domain=''", lcuuid).First(&resultFloatingIP).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), floatingIP.Base.Lcuuid, resultFloatingIP.Base.Lcuuid)

	resultFloatingIP = new(mysql.FloatingIP)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultFloatingIP)
	assert.Equal(t.T(), floatingIP.Base.Lcuuid, resultFloatingIP.Base.Lcuuid)

	resultFloatingIP = new(mysql.FloatingIP)
	result := t.db.Where("lcuuid = ? and ip = null", lcuuid).Find(&resultFloatingIP)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
