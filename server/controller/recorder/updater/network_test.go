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
)

func newCloudNetwork() cloudmodel.Network {
	lcuuid := uuid.New().String()
	return cloudmodel.Network{
		Lcuuid:         lcuuid,
		Name:           lcuuid[:8],
		SegmentationID: randID(),
	}
}

func (t *SuiteTest) getNetworkMock(mockDB bool) (*cache.Cache, cloudmodel.Network) {
	cloudItem := newCloudNetwork()
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.Network{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid})
		cache_.Networks[cloudItem.Lcuuid] = &cache.Network{DiffBase: cache.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddNetworkSucess() {
	cache_, cloudItem := t.getNetworkMock(false)
	vpcID := randID()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVPCIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return vpcID, true
	})
	defer monkey.Reset()
	assert.Equal(t.T(), len(cache_.Networks), 0)

	updater := NewNetwork(cache_, []cloudmodel.Network{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.Network
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache_.Networks), 1)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Network{})
}

func (t *SuiteTest) TestHandleUpdateNetworkSucess() {
	cache, cloudItem := t.getNetworkMock(true)
	cloudItem.Name = cloudItem.Name + "new"
	cloudItem.SegmentationID = cloudItem.SegmentationID + 1

	updater := NewNetwork(cache, []cloudmodel.Network{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.Network
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache.Networks), 1)
	assert.Equal(t.T(), addedItem.Name, cloudItem.Name)
	assert.Equal(t.T(), addedItem.SegmentationID, cloudItem.SegmentationID)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Network{})
}

func (t *SuiteTest) TestHandleDeleteNetworkSucess() {
	cache, cloudItem := t.getNetworkMock(true)

	updater := NewNetwork(cache, []cloudmodel.Network{cloudItem})
	updater.HandleDelete()

	var addedItem *mysql.Network
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	assert.Equal(t.T(), len(cache.Networks), 0)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.Network{})
}
