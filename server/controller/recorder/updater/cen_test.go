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
	"strconv"

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

func newCloudCEN() cloudmodel.CEN {
	lcuuid := uuid.New().String()
	return cloudmodel.CEN{
		Lcuuid:     lcuuid,
		Name:       lcuuid[:8],
		VPCLcuuids: []string{uuid.NewString()},
	}
}

func (t *SuiteTest) getCENMock(mockDB bool) (*cache.Cache, cloudmodel.CEN) {
	cloudItem := newCloudCEN()
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.CEN{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid})
		cache_.DiffBaseDataSet.CENs[cloudItem.Lcuuid] = &diffbase.CEN{DiffBase: diffbase.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddCENSucess() {
	cache_, cloudItem := t.getCENMock(false)
	vpcID := randID()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVPCIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return vpcID, true
	})
	defer monkey.Reset()
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.CENs), 0)

	updater := NewCEN(cache_, []cloudmodel.CEN{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.CEN
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.CENs), 1)
	assert.Equal(t.T(), addedItem.VPCIDs, strconv.Itoa(vpcID))

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.CEN{})
}

func (t *SuiteTest) TestHandleUpdateCENSucess() {
	cache, cloudItem := t.getCENMock(true)
	cloudItem.Name = cloudItem.Name + "new"

	updater := NewCEN(cache, []cloudmodel.CEN{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.CEN
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), addedItem.Name, cloudItem.Name)
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.CENs), 1)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.CEN{})
}

func (t *SuiteTest) TestHandleDeleteCENSucess() {
	cache, cloudItem := t.getCENMock(true)

	updater := NewCEN(cache, []cloudmodel.CEN{})
	updater.HandleDelete()

	var addedItem *mysql.CEN
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.CENs), 0)
}
