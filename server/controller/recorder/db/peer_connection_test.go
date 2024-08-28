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

	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/mysql/model"
)

func newDBPeerConnection() *mysqlmodel.PeerConnection {
	return &mysqlmodel.PeerConnection{Base: mysqlmodel.Base{Lcuuid: uuid.New().String()}, Name: uuid.New().String()}
}

func (t *SuiteTest) TestAddPeerConnectionBatchSuccess() {
	operator := NewPeerConnection()
	itemToAdd := newDBPeerConnection()

	_, ok := operator.AddBatch([]*mysqlmodel.PeerConnection{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysqlmodel.PeerConnection
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Lcuuid, itemToAdd.Lcuuid)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.PeerConnection{})
}

func (t *SuiteTest) TestUpdatePeerConnectionSuccess() {
	operator := NewPeerConnection()
	addedItem := newDBPeerConnection()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"name": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysqlmodel.PeerConnection
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Name, updateInfo["name"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysqlmodel.PeerConnection{})
}

func (t *SuiteTest) TestDeletePeerConnectionBatchSuccess() {
	operator := NewPeerConnection()
	addedItem := newDBPeerConnection()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysqlmodel.PeerConnection
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
