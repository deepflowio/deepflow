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

func newCloudDHCPPort() cloudmodel.DHCPPort {
	lcuuid := uuid.NewString()
	return cloudmodel.DHCPPort{
		Lcuuid: lcuuid,
		Name:   lcuuid[:8],
	}
}

func (t *SuiteTest) getDHCPPortMock(mockDB bool) (*cache.Cache, cloudmodel.DHCPPort) {
	cloudItem := newCloudDHCPPort()
	domainLcuuid := uuid.NewString()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.DHCPPort{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid})
		cache_.DiffBaseDataSet.DHCPPorts[cloudItem.Lcuuid] = &diffbase.DHCPPort{DiffBase: diffbase.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddDHCPPortSucess() {
	cache_, cloudItem := t.getDHCPPortMock(false)
	vpcID := randID()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVPCIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return vpcID, true
	})
	defer monkey.Reset()
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.DHCPPorts), 0)

	updater := NewDHCPPort(cache_, []cloudmodel.DHCPPort{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.DHCPPort
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.DHCPPorts), 1)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.DHCPPort{})
}

func (t *SuiteTest) TestHandleUpdateDHCPPortSucess() {
	cache, cloudItem := t.getDHCPPortMock(true)
	cloudItem.Name = cloudItem.Name + "new"

	updater := NewDHCPPort(cache, []cloudmodel.DHCPPort{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.DHCPPort
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), addedItem.Name, cloudItem.Name)
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.DHCPPorts), 1)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.DHCPPort{})
}

func (t *SuiteTest) TestHandleDeleteDHCPPortSucess() {
	cache, cloudItem := t.getDHCPPortMock(true)

	updater := NewDHCPPort(cache, []cloudmodel.DHCPPort{cloudItem})
	updater.HandleDelete()

	var addedItem *mysql.DHCPPort
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.DHCPPorts), 0)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.DHCPPort{})
}
