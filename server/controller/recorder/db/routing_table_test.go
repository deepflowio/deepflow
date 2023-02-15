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

func newDBRoutingTable() *mysql.RoutingTable {
	return &mysql.RoutingTable{Base: mysql.Base{Lcuuid: uuid.New().String()}, Nexthop: uuid.New().String()}
}

func (t *SuiteTest) TestAddRoutingTableBatchSuccess() {
	operator := NewRoutingTable()
	itemToAdd := newDBRoutingTable()

	_, ok := operator.AddBatch([]*mysql.RoutingTable{itemToAdd})
	assert.True(t.T(), ok)

	var addedItem *mysql.RoutingTable
	t.db.Where("lcuuid = ?", itemToAdd.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), addedItem.Nexthop, itemToAdd.Nexthop)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.RoutingTable{})
}

func (t *SuiteTest) TestUpdateRoutingTableSuccess() {
	operator := NewRoutingTable()
	addedItem := newDBRoutingTable()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	updateInfo := map[string]interface{}{"nexthop": uuid.New().String()}
	_, ok := operator.Update(addedItem.Lcuuid, updateInfo)
	assert.True(t.T(), ok)

	var updatedItem *mysql.RoutingTable
	t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), updatedItem.Nexthop, updateInfo["nexthop"])

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.RoutingTable{})
}

func (t *SuiteTest) TestDeleteRoutingTableBatchSuccess() {
	operator := NewRoutingTable()
	addedItem := newDBRoutingTable()
	result := t.db.Create(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))

	assert.True(t.T(), operator.DeleteBatch([]string{addedItem.Lcuuid}))
	var deletedItem *mysql.RoutingTable
	result = t.db.Where("lcuuid = ?", addedItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
}
