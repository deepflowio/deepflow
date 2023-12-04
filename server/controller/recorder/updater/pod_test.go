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

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/controller/recorder/test"
)

func newCloudPod() cloudmodel.Pod {
	lcuuid := uuid.New().String()
	return cloudmodel.Pod{
		Lcuuid: lcuuid,
		Name:   lcuuid[:8],
		Label:  lcuuid[:6],
	}
}

func (t *SuiteTest) getPodMock(mockDB bool) (*cache.Cache, cloudmodel.Pod) {
	cloudItem := newCloudPod()
	domainLcuuid := uuid.New().String()

	c := cache.NewCache(domainLcuuid)
	if mockDB {
		t.db.Create(&mysql.Pod{Name: cloudItem.Name, Base: mysql.Base{Lcuuid: cloudItem.Lcuuid}, Domain: domainLcuuid, Label: cloudItem.Label})
		c.DiffBaseDataSet.Pods[cloudItem.Lcuuid] = &diffbase.Pod{DiffBase: diffbase.DiffBase{Lcuuid: cloudItem.Lcuuid}, Name: cloudItem.Name, Label: cloudItem.Label}
	}

	c.SetSequence(c.GetSequence() + 1)

	return c, cloudItem
}

func (t *SuiteTest) TestHandleAddPodSucess() {
	c, cloudItem := t.getPodMock(false)
	assert.Equal(t.T(), len(c.DiffBaseDataSet.Pods), 0)
	vpcID := randID()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&c.ToolDataSet), "GetVPCIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return vpcID, true
	})
	defer monkey.Reset()
	podNodeID := randID()
	monkey1 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodNodeIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return podNodeID, true
	})
	defer monkey1.Reset()
	podNamespaceID := randID()
	monkey2 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodNamespaceIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return podNamespaceID, true
	})
	defer monkey2.Reset()
	podClusterID := randID()
	monkey3 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodClusterIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return podClusterID, true
	})
	defer monkey3.Reset()
	podGroupID := randID()
	monkey4 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&c.ToolDataSet), "GetPodGroupIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return podGroupID, true
	})
	defer monkey4.Reset()

	updater := NewPod(c, []cloudmodel.Pod{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.Pod
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(c.DiffBaseDataSet.Pods), 1)
	assert.Equal(t.T(), cloudItem.Label, addedItem.Label)

	test.ClearDBData[mysql.Pod](t.db)
}

func (t *SuiteTest) TestHandleUpdatePodSucess() {
	cache, cloudItem := t.getPodMock(true)
	cloudItem.Name = cloudItem.Name + "new"
	cloudItem.Label = cloudItem.Label + "new"

	updater := NewPod(cache, []cloudmodel.Pod{cloudItem})
	updater.HandleAddAndUpdate()

	var addedItem *mysql.Pod
	result := t.db.Where("lcuuid = ?", cloudItem.Lcuuid).Find(&addedItem)
	assert.Equal(t.T(), result.RowsAffected, int64(1))
	assert.Equal(t.T(), len(cache.DiffBaseDataSet.Pods), 1)
	assert.Equal(t.T(), addedItem.Label, cloudItem.Label)

	test.ClearDBData[mysql.Pod](t.db)
}
