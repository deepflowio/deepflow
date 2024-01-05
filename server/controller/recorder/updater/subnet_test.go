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

func newCloudSubnet() cloudmodel.Subnet {
	lcuuid := uuid.New().String()
	return cloudmodel.Subnet{
		Lcuuid: lcuuid,
		Name:   lcuuid[:8],
		CIDR:   "108.0.0.0/16",
	}
}

func (t *SuiteTest) getSubnetMock(mockDB bool) (*cache.Cache, cloudmodel.Subnet) {
	cloudItem := newCloudSubnet()
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.Subnet{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}})
		cache_.DiffBaseDataSet.Subnets[cloudItem.Lcuuid] = &diffbase.Subnet{DiffBase: diffbase.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddSubnetSucess() {
	cache_, cloudItem := t.getSubnetMock(false)
	networkID := randID()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetNetworkIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return networkID, true
	})
	defer monkey.Reset()
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.Subnets), 0)

	updater := NewSubnet(cache_, []cloudmodel.Subnet{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.Subnet
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), int64(1), result.RowsAffected)
	assert.Equal(t.T(), 1, len(cache_.DiffBaseDataSet.Subnets))

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Subnet{})
}

func (t *SuiteTest) TestHandleUpdateSubnetSucess() {
	cache, cloudItem := t.getSubnetMock(true)
	cloudItem.Name = cloudItem.Name + "new"

	updater := NewSubnet(cache, []cloudmodel.Subnet{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.Subnet
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.Subnets), 1)
	assert.Equal(t.T(), addedItem.Name, cloudItem.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Subnet{})
}

func (t *SuiteTest) TestHandleDeleteSubnetSucess() {
	cache, cloudItem := t.getSubnetMock(true)

	updater := NewSubnet(cache, []cloudmodel.Subnet{cloudItem})
	updater.HandleDelete()

	var addedItem *mysql.Subnet
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.Subnets), 0)
}
