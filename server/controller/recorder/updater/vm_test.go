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
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

func newCloudVM() cloudmodel.VM {
	lcuuid := uuid.New().String()
	return cloudmodel.VM{
		Lcuuid:       uuid.New().String(),
		Name:         lcuuid[:8],
		Label:        lcuuid[:6],
		HType:        1,
		State:        4,
		LaunchServer: "10.1.1.10",
		VPCLcuuid:    uuid.New().String(),
		AZLcuuid:     uuid.New().String(),
		RegionLcuuid: uuid.New().String(),
	}
}

func (t *SuiteTest) getVMMock(mockDB bool) (*cache.Cache, cloudmodel.VM) {
	cloudItem := newCloudVM()
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.VM{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, CreateMethod: common.CREATE_METHOD_LEARN, Domain: domainLcuuid})
		cache_.DiffBaseDataSet.VMs[cloudItem.Lcuuid] = &diffbase.VM{DiffBase: diffbase.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name, VPCLcuuid: cloudItem.VPCLcuuid}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddVMSucess() {
	cache_, cloudItem := t.getVMMock(false)
	vpcID := randID()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&cache_.ToolDataSet), "GetVPCIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return vpcID, true
	})
	defer monkey.Reset()
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.VMs), 0)

	updater := NewVM(cache_, []cloudmodel.VM{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.VM
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache_.DiffBaseDataSet.VMs), 1)
	assert.Equal(t.T(), addedItem.VPCID, vpcID)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VM{})
}

func (t *SuiteTest) TestHandleUpdateVMSucess() {
	cache, cloudItem := t.getVMMock(true)
	cloudItem.Name = cloudItem.Name + "-update"

	updater := NewVM(cache, []cloudmodel.VM{cloudItem})
	updater.HandleAddAndUpdate()

	var updatedItem *mysql.VM
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), updatedItem.Name, cloudItem.Name)

	diffBase := cache.DiffBaseDataSet.VMs[cloudItem.Lcuuid]
	assert.Equal(t.T(), cache.GetSequence(), diffBase.GetSequence())

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VM{})
}

func (t *SuiteTest) TestHandleDeleteVMSuccess() {
	cache, cloudItem := t.getVMMock(true)

	updater := NewVM(cache, []cloudmodel.VM{})
	updater.HandleAddAndUpdate()
	updater.HandleDelete()

	var deletedItem *mysql.VM
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&deletedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.VPC{})
}
