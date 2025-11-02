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

	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
)

func newDBVIP() *mysqlmodel.VIP {
	return &mysqlmodel.VIP{
		Base:   mysqlmodel.Base{Lcuuid: uuid.New().String()},
		IP:     "192.168.1.216",
		VTapID: 216,
	}
}

func (t *SuiteTest) TestAddVIPBatchSuccess() {
	operator := NewVIP()
	itemToAdd := newDBVIP()

	_, ok := operator.AddBatch([]*mysqlmodel.VIP{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysqlmodel.VIP
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.VIP{})
}

func (t *SuiteTest) TestUpdateVIPSuccess() {
	operator := NewVIP()
	addedItem := newDBVIP()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"ip": "192.168.1.217"}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysqlmodel.VIP
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.IP, updateInfo["ip"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.VIP{})
}

func (t *SuiteTest) TestDeleteVIPBatchSuccess() {
	operator := NewVIP()
	addedItem := newDBVIP()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysqlmodel.VIP
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestVIPCreateAndFind() {
	lcuuid := uuid.New().String()
	vip := &mysqlmodel.VIP{
		Base: mysqlmodel.Base{Lcuuid: lcuuid},
	}
	t.db.Create(vip)
	var resultVIP *mysqlmodel.VIP
	err := t.db.Where("lcuuid = ?", lcuuid).First(&resultVIP).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), vip.Base.Lcuuid, resultVIP.Base.Lcuuid)

	resultVIP = new(mysqlmodel.VIP)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultVIP)
	assert.Equal(t.T(), vip.Base.Lcuuid, resultVIP.Base.Lcuuid)

	resultVIP = new(mysqlmodel.VIP)
	result := t.db.Where("lcuuid = ? and ip = ''", lcuuid).Find(&resultVIP)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
