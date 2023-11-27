/*
 * Copyright (c) 2023 Yunshan Networks
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

package updater

import (
	"reflect"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

func newCloudRoutingTable() cloudmodel.RoutingTable {
	lcuuid := uuid.New().String()
	return cloudmodel.RoutingTable{
		Lcuuid:      lcuuid,
		Destination: uuid.NewString(),
	}
}

func (t *SuiteTest) getRoutingTableMock(mockDB bool) (*cache.Cache, cloudmodel.RoutingTable) {
	cloudItem := newCloudRoutingTable()
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.RoutingTable{Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Destination: cloudItem.Destination})
		cache_.DiffBaseDataSet.RoutingTables[cloudItem.Lcuuid] = &diffbase.RoutingTable{DiffBase: diffbase.DiffBase{Lcuuid: cloudItem.Lcuuid}}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddRoutingTableSucess() {
	cache_, cloudItem := t.getRoutingTableMock(false)
	vrouterID := randID()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVRouterIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return vrouterID, true
	})
	defer monkey.Reset()
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.RoutingTables), 0)

	updater := NewRoutingTable(cache_, []cloudmodel.RoutingTable{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.RoutingTable
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.RoutingTables), 1)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.RoutingTable{})
}

func (t *SuiteTest) TestHandleUpdateRoutingTableSucess() {
	cache, cloudItem := t.getRoutingTableMock(true)
	cloudItem.Destination = uuid.NewString()

	updater := NewRoutingTable(cache, []cloudmodel.RoutingTable{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.RoutingTable
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.RoutingTables), 1)
	assert.Equal(t.T(), addedItem.Destination, cloudItem.Destination)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.RoutingTable{})
}

func (t *SuiteTest) TestHandleDeleteRoutingTableSucess() {
	cache, cloudItem := t.getRoutingTableMock(true)

	updater := NewRoutingTable(cache, []cloudmodel.RoutingTable{cloudItem})
	updater.HandleDelete()

	var addedItem *mysql.RoutingTable
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.RoutingTables), 0)
}
