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
	"fmt"
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

func newCloudVRouter() cloudmodel.VRouter {
	lcuuid := uuid.New().String()
	return cloudmodel.VRouter{
		Lcuuid: lcuuid,
		Name:   lcuuid[:8],
	}
}

func (t *SuiteTest) getVRouterMock(mockDB bool) (*cache.Cache, cloudmodel.VRouter) {
	cloudItem := newCloudVRouter()
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.VRouter{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid})
		cache_.DiffBaseDataSet.VRouters[cloudItem.Lcuuid] = &diffbase.VRouter{DiffBase: diffbase.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddVRouterSucess() {
	cache_, cloudItem := t.getVRouterMock(false)
	vpcID := randID()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVPCIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return vpcID, true
	})
	defer monkey.Reset()
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.VRouters), 0)

	updater := NewVRouter(cache_, []cloudmodel.VRouter{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.VRouter
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.VRouters), 1)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VRouter{})
}

func (t *SuiteTest) TestHandleUpdateVRouterSucess() {
	cache_, cloudItem := t.getVRouterMock(true)
	cloudItem.Name = cloudItem.Name + "new"
	cloudItem.VPCLcuuid = uuid.NewString()
	newVPCID := randID()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVPCIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return newVPCID, true
	})
	defer monkey.Reset()

	updater := NewVRouter(cache_, []cloudmodel.VRouter{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.VRouter
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.VRouters), 1)
	fmt.Println(addedItem)
	assert.Equal(t.T(), addedItem.Name, cloudItem.Name)
	assert.Equal(t.T(), addedItem.VPCID, newVPCID)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VRouter{})
}

func (t *SuiteTest) TestHandleDeleteVRouterSucess() {
	cache, cloudItem := t.getVRouterMock(true)

	updater := NewVRouter(cache, []cloudmodel.VRouter{cloudItem})
	updater.HandleDelete()

	var addedItem *mysql.VRouter
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.VRouters), 0)
}
