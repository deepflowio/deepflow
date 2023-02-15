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

func newDBVM() *mysql.VM {
	return &mysql.VM{Base: mysql.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddVMBatchSuccess() {
	operator := NewVM()
	itemToAdd := newDBVM()

	_, ok := operator.AddBatch([]*mysql.VM{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.VM
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Name, itemToAdd.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VM{})
}

func (t *SuiteTest) TestUpdateVMSuccess() {
	operator := NewVM()
	addedItem := newDBVM()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.VM
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VM{})
}

func (t *SuiteTest) TestDeleteVMBatchSuccess() {
	operator := NewVM()
	addedItem := newDBVM()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	vmPodNodeConn := newDBVMPodNodeConnection()
	vmPodNodeConn.VMID = addedItem.ID
	result = t.db.Create(&vmPodNodeConn)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.VM
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	var deletedVMPodNodeConn *mysql.VMPodNodeConnection
	result = t.db.Where("lcuuid = ?", vmPodNodeConn.Lcuuid).Find(&deletedVMPodNodeConn)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}

func (t *SuiteTest) TestVMCreateAndFind() {
	lcuuid := uuid.New().String()
	vm := &mysql.VM{
		Base: mysql.Base{Lcuuid: lcuuid},
	}
	t.db.Create(vm)
	var resultVM *mysql.VM
	err := t.db.Where("lcuuid = ? and name='' and alias='' and label='' and launch_server='' "+
		"and az='' and region='' and uid=''", lcuuid).First(&resultVM).Error
	assert.Equal(t.T(), nil, err)
	assert.Equal(t.T(), vm.Base.Lcuuid, resultVM.Base.Lcuuid)

	resultVM = new(mysql.VM)
	t.db.Where("lcuuid = ?", lcuuid).Find(&resultVM)
	assert.Equal(t.T(), vm.Base.Lcuuid, resultVM.Base.Lcuuid)

	resultVM = new(mysql.VM)
	result := t.db.Where("lcuuid = ? and name = null", lcuuid).Find(&resultVM)
	assert.Equal(t.T(), nil, result.Error)
	assert.Equal(t.T(), int64(0), result.RowsAffected)
}
