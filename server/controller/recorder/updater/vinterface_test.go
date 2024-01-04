/*
 * Copyright (c) 2024 Yunshan VInterfaces
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
	"github.com/bxcodec/faker/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

func newCloudVInterface() cloudmodel.VInterface {
	lcuuid := uuid.New().String()
	return cloudmodel.VInterface{
		Lcuuid: lcuuid,
		Name:   lcuuid[:8],
		Type:   common.VIF_TYPE_LAN,
	}
}

func (t *SuiteTest) getVInterfaceMock(mockDB bool) (*cache.Cache, cloudmodel.VInterface, cloudmodel.IP) {
	cloudItem := newCloudVInterface()
	cloudIP := cloudmodel.IP{IP: faker.IPv4(), Lcuuid: uuid.NewString(), VInterfaceLcuuid: cloudItem.Lcuuid}
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		vifID := 100
		t.db.Create(&mysql.VInterface{Name: cloudItem.Name, Base: mysql.Base{ID: vifID, Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid})
		cache_.DiffBaseDataSet.VInterfaces[cloudItem.Lcuuid] = &diffbase.VInterface{DiffBase: diffbase.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name}

		t.db.Create(&mysql.LANIP{Base: mysql.Base{Lcuuid: cloudIP.Lcuuid}, Domain: domainLcuuid, VInterfaceID: vifID})
		cache_.DiffBaseDataSet.LANIPs[cloudIP.Lcuuid] = &diffbase.LANIP{DiffBase: diffbase.DiffBase{Lcuuid: cloudItem.Lcuuid}}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem, cloudIP
}

func (t *SuiteTest) TestHandleUpdateVInterfaceSucess() {
	cache_, cloudItem, cloudIP := t.getVInterfaceMock(true)
	cloudItem.Type = common.VIF_TYPE_WAN
	assert.Equal(t.T(), 1, len(cache_.DiffBaseDataSet.LANIPs))

	updater := NewVInterface(cache_, []cloudmodel.VInterface{cloudItem}, nil)
	ipUpdater := NewIP(cache_, []cloudmodel.IP{cloudIP}, nil)
	updater.HandleAddAndUpdate()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVInterfaceIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return 100, true
	})
	defer monkey.Reset()
	ipUpdater.HandleAddAndUpdate()
	updater.HandleDelete()
	ipUpdater.HandleDelete()

	var addedItem *mysql.VInterface
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.VInterfaces), 1)
	assert.Equal(t.T(), addedItem.Type, cloudItem.Type)
	var wanIP *mysql.WANIP
	t.db.Where("vifid = ?", addedItem.ID).Find(&wanIP)
	assert.Equal(t.T(), cloudIP.IP, wanIP.IP)
	assert.Equal(t.T(), 1, len(cache_.DiffBaseDataSet.WANIPs))
	assert.Equal(t.T(), 0, len(cache_.DiffBaseDataSet.LANIPs))

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VInterface{})
	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.WANIP{})
}
