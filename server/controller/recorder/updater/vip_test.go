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
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
)

func (t *SuiteTest) getVIPCacheAndCloudItem() (*cache.Cache, cloudmodel.VIP) {
	c := cache.NewCache(uuid.New().String())
	c.SetSequence(c.GetSequence() + 1)
	cloudItem := cloudmodel.VIP{
		Lcuuid: uuid.New().String(),
		IP:     "192.168.1.216",
		VTapID: 216,
	}
	return c, cloudItem
}

func (t *SuiteTest) TestHandleAddVIPSuccess() {
	c, cloudItem := t.getVIPCacheAndCloudItem()
	updater := NewVIP(c, []cloudmodel.VIP{cloudItem})
	updater.HandleAddAndUpdate()

	var result *mysql.VIP
	dbResult := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&result)
	assert.Equal(t.T(), dbResult.RowsAffected, int64(1))
	assert.Equal(t.T(), cloudItem.IP, result.IP)
	assert.Equal(t.T(), cloudItem.VTapID, result.VTapID)
}

func (t *SuiteTest) TestHandleUpdateVIPSuccess() {
	c, cloudItem := t.getVIPCacheAndCloudItem()
	updater := NewVIP(c, []cloudmodel.VIP{cloudItem})
	updater.HandleAddAndUpdate()

	wantIP := "192.168.1.217"
	var wantVtapID uint32 = 217
	cloudItem.IP, cloudItem.VTapID = wantIP, wantVtapID
	updater.cloudData = []cloudmodel.VIP{cloudItem}
	updater.HandleAddAndUpdate()

	var result *mysql.VIP
	dbResult := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&result)
	assert.Equal(t.T(), dbResult.RowsAffected, int64(1))
	assert.Equal(t.T(), wantIP, result.IP)
	assert.Equal(t.T(), wantVtapID, result.VTapID)
}

func (t *SuiteTest) TestHandleDeleteVIPSuccess() {
	c, cloudItem := t.getVIPCacheAndCloudItem()
	updater := NewVIP(c, []cloudmodel.VIP{cloudItem})
	updater.HandleAddAndUpdate()

	updater.cache.SetSequence(updater.cache.GetSequence() + 1)
	updater.HandleDelete()

	var result *mysql.VIP
	dbResult := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&result)
	assert.Equal(t.T(), dbResult.RowsAffected, int64(0))
	if updater.cache.DiffBaseDataSet.VIP[cloudItem.Lcuuid] != nil {
		t.Errorf(nil, "want cache: nil, actual cache: %+v", updater.cache.DiffBaseDataSet.VIP[cloudItem.Lcuuid])
	}
}
