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
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
)

func newCloudAZ() cloudmodel.AZ {
	lcuuid := uuid.New().String()
	return cloudmodel.AZ{
		Lcuuid:       lcuuid,
		Name:         lcuuid[:8],
		Label:        lcuuid[:6],
		RegionLcuuid: uuid.New().String(),
	}
}

func (t *SuiteTest) getAZMock(mockDB bool) (*cache.Cache, cloudmodel.AZ) {
	cloudItem := newCloudAZ()
	domainLcuuid := uuid.New().String()

	wholeCache := cache.NewCache(domainLcuuid)
	if mockDB {
		dbItem := new(mysql.AZ)
		dbItem.Lcuuid = cloudItem.Lcuuid
		dbItem.Name = cloudItem.Name
		t.db.Create(dbItem)
		wholeCache.AZs[cloudItem.Lcuuid] = &cache.AZ{DiffBase: cache.DiffBase{Lcuuid: cloudItem.Lcuuid}}
	}

	wholeCache.SetSequence(wholeCache.GetSequence() + 1)

	return wholeCache, cloudItem
}

func (t *SuiteTest) TestHandleAddAZSucess() {
	cache, cloudItem := t.getAZMock(false)
	assert.Equal(t.T(), len(cache.AZs), 0)

	updater := NewAZ(cache, []cloudmodel.AZ{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.AZ
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache.AZs), 1)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.AZ{})
}

func (t *SuiteTest) TestHandleUpdateAZSucess() {
	cache, cloudItem := t.getAZMock(true)
	cloudItem.Name = cloudItem.Name + "new"

	updater := NewAZ(cache, []cloudmodel.AZ{cloudItem})
	updater.HandleAddAndUpdate()

	var updatedItem *mysql.AZ
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&updatedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), updatedItem.Name, cloudItem.Name)
	assert.Equal(t.T(), cache.AZs[cloudItem.Lcuuid].Name, cloudItem.Name)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.AZ{})
}

func (t *SuiteTest) TestHandleDeleteAZSucess() {
	cache, cloudItem := t.getAZMock(true)

	updater := NewAZ(cache, []cloudmodel.AZ{})
	updater.HandleDelete()

	var addedItem *mysql.AZ
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.AZ{})
}
