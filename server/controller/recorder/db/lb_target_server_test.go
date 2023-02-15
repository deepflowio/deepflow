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
	"math/rand"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func newDBLBTargetServer() *mysql.LBTargetServer {
	return &mysql.LBTargetServer{Base: mysql.Base{Lcuuid: uuid.New().String()}, Port: rand.Intn(65535)}
}

func (t *SuiteTest) TestAddLBTargetServerBatchSuccess() {
	operator := NewLBTargetServer()
	itemToAdd := newDBLBTargetServer()

	_, ok := operator.AddBatch([]*mysql.LBTargetServer{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.LBTargetServer
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Port, itemToAdd.Port)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.LBTargetServer{})
}

func (t *SuiteTest) TestUpdateLBTargetServerSuccess() {
	operator := NewLBTargetServer()
	addedItem := newDBLBTargetServer()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"port": rand.Intn(65535)}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.LBTargetServer
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Port, updateInfo["port"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.LBTargetServer{})
}

func (t *SuiteTest) TestDeleteLBTargetServerBatchSuccess() {
	operator := NewLBTargetServer()
	addedItem := newDBLBTargetServer()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.LBTargetServer
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
