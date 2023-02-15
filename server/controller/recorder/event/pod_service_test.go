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

package event

import (
	"reflect"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"

	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
)

func TestAddPodService(t *testing.T) {
	ds := cache.NewToolDataSet()
	id := RandID()
	name := RandName()
	eq := NewEventQueue()
	dbItem := NewPodService(&ds, eq)
	dbItem.ProduceByAdd([]*mysql.PodService{{Base: mysql.Base{ID: id}, Name: name}})
	assert.Equal(t, 1, eq.Len())
	e := eq.Get().(*eventapi.ResourceEvent)
	assert.Equal(t, eventapi.RESOURCE_EVENT_TYPE_CREATE, e.Type)
	assert.Equal(t, uint32(common.VIF_DEVICE_TYPE_POD_SERVICE), e.InstanceType)
	assert.Equal(t, uint32(id), e.InstanceID)
	assert.Equal(t, name, e.InstanceName)

	dbItem.ProduceByAdd([]*mysql.PodService{{Name: RandName()}, {Name: RandName()}})
	assert.Equal(t, 2, eq.Len())
}

func TestDeletePodService(t *testing.T) {
	ds := cache.NewToolDataSet()
	id := RandID()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&ds), "GetPodServiceIDByLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return id, true
	})
	defer monkey.Reset()

	name := RandName()
	monkey1 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&ds), "GetPodServiceNameByID", func(_ *cache.ToolDataSet, _ int) (string, bool) {
		return name, true
	})
	defer monkey1.Reset()

	eq := NewEventQueue()
	wanIP := NewPodService(&ds, eq)
	wanIP.ProduceByDelete([]string{RandLcuuid()})
	assert.Equal(t, 1, eq.Len())
	e := eq.Get().(*eventapi.ResourceEvent)
	assert.Equal(t, eventapi.RESOURCE_EVENT_TYPE_DELETE, e.Type)
	assert.Equal(t, uint32(common.VIF_DEVICE_TYPE_POD_SERVICE), e.InstanceType)
	assert.Equal(t, uint32(id), e.InstanceID)
	assert.Equal(t, name, e.InstanceName)
}
