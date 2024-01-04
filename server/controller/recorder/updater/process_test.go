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

func (t *SuiteTest) getCacheAndCloudItem() (*cache.Cache, cloudmodel.Process) {
	c := cache.NewCache(uuid.New().String())
	c.SetSequence(c.GetSequence() + 1)
	cloudItem := cloudmodel.Process{
		Lcuuid: uuid.New().String(),
		Name:   "process",
	}
	return c, cloudItem
}

func (t *SuiteTest) TestHandleAddProcessSuccess() {
	c, cloudItem := t.getCacheAndCloudItem()
	updater := NewProcess(c, []cloudmodel.Process{cloudItem})
	updater.HandleAddAndUpdate()

	var result *mysql.Process
	dbResult := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&result)
	assert.Equal(t.T(), dbResult.RowsAffected, int64(1))
	assert.Equal(t.T(), cloudItem.Name, result.Name)
}

func (t *SuiteTest) TestHandleUpdateProcessSuccess() {
	c, cloudItem := t.getCacheAndCloudItem()
	updater := NewProcess(c, []cloudmodel.Process{cloudItem})
	updater.HandleAddAndUpdate()

	wantName := "process-updated"
	wantOSAPPTags := "app:skywalking"
	cloudItem.Name, cloudItem.OSAPPTags = wantName, wantOSAPPTags
	updater.cloudData = []cloudmodel.Process{cloudItem}
	updater.HandleAddAndUpdate()

	var result *mysql.Process
	dbResult := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&result)
	assert.Equal(t.T(), dbResult.RowsAffected, int64(1))
	assert.Equal(t.T(), wantName, result.Name)
	assert.Equal(t.T(), wantOSAPPTags, result.OSAPPTags)
}

func (t *SuiteTest) TestHandleDeleteProcessSuccess() {
	c, cloudItem := t.getCacheAndCloudItem()
	updater := NewProcess(c, []cloudmodel.Process{cloudItem})
	updater.HandleAddAndUpdate()

	updater.cache.SetSequence(updater.cache.GetSequence() + 1)
	updater.HandleDelete()

	var result *mysql.Process
	dbResult := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&result)
	assert.Equal(t.T(), dbResult.RowsAffected, int64(0))
	if updater.cache.DiffBaseDataSet.Process[cloudItem.Lcuuid] != nil {
		t.Errorf(nil, "want cache: nil, actual cache: %+v", updater.cache.DiffBaseDataSet.Process[cloudItem.Lcuuid])
	}
}
