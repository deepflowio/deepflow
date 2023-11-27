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
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
)

func newCloudSubDomain() cloudmodel.SubDomain {
	lcuuid := uuid.New().String()
	return cloudmodel.SubDomain{
		Lcuuid: lcuuid,
		Name:   lcuuid[:8],
	}
}

func (t *SuiteTest) getSubDomainMock(mockDB bool) (*cache.Cache, cloudmodel.SubDomain) {
	cloudItem := newCloudSubDomain()
	domainLcuuid := uuid.New().String()

	cache_ := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.SubDomain{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid})
		cache_.DiffBaseDataSet.SubDomains[cloudItem.Lcuuid] = &diffbase.SubDomain{DiffBase: diffbase.DiffBase{Lcuuid: cloudItem.Lcuuid}}
	}

	cache_.SetSequence(cache_.GetSequence() + 1)

	return cache_, cloudItem
}

func (t *SuiteTest) TestHandleAddSubDomainSucess() {
	cache, cloudItem := t.getSubDomainMock(false)
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.SubDomains), 0)

	updater := NewSubDomain(cache, []cloudmodel.SubDomain{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.SubDomain
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.SubDomains), 1)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.SubDomain{})
}

func (t *SuiteTest) TestHandleDeleteSubDomainSucess() {
	cache, cloudItem := t.getSubDomainMock(true)

	updater := NewSubDomain(cache, []cloudmodel.SubDomain{cloudItem})
	updater.HandleDelete()

	var addedItem *mysql.SubDomain
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(0))
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.SubDomains), 0)

	t.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&mysql.SubDomain{})
}
