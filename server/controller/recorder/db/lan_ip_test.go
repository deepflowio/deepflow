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
	"math/rand"
	"strconv"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func randomIP() string {
	return "192.168." + strconv.Itoa(rand.Intn(256)) + "." + strconv.Itoa(rand.Intn(256))
}

func newDBLANIP() *mysql.LANIP {
	return &mysql.LANIP{Base: mysql.Base{Lcuuid: uuid.New().String()}, IP: randomIP()}
}

func (t *SuiteTest) TestAddLANIPBatchSuccess() {
	operator := NewLANIP()
	itemToAdd := newDBLANIP()

	_, ok := operator.AddBatch([]*mysql.LANIP{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.LANIP
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.IP, itemToAdd.IP)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.LANIP{})
}

func (t *SuiteTest) TestDeleteLANIPBatchSuccess() {
	operator := NewLANIP()
	addedItem := newDBLANIP()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.LANIP
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestLANIPCreateAndFind() {
	lcuuid := uuid.New().String()
	lanIP := &mysql.LANIP{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(lanIP)
	var resultLANIP *mysql.LANIP
	err := t.db.Where("lcuuid = ? and ip='' and netmask='' and gateway=''"+
		"and sub_domain='' and domain=''", lcuuid).First(&resultLANIP).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), lanIP.Base.Lcuuid, resultLANIP.Base.Lcuuid)

	resultLANIP = new(mysql.LANIP)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultLANIP)
	assert.Equal(t.T(), lanIP.Base.Lcuuid, resultLANIP.Base.Lcuuid)

	resultLANIP = new(mysql.LANIP)
	result := t.db.Where("lcuuid = ? and ip = null", lcuuid).Find(&resultLANIP)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
