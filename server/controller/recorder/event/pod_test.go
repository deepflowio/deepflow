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

package event

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"

	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/diffbase"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
	"github.com/deepflowio/deepflow/server/libs/eventapi"
)

func TestAddPod(t *testing.T) {
	ds := tool.NewDataSet()
	id := RandID()
	name := RandName()
	eq := NewEventQueue()
	em := NewPod(ds, eq)
	em.ProduceByAdd([]*mysql.Pod{{Base: mysql.Base{ID: id}, Name: name}})
	assert.Equal(t, 1, eq.Len())
	e := eq.Get().(*eventapi.ResourceEvent)
	assert.Equal(t, eventapi.RESOURCE_EVENT_TYPE_CREATE, e.Type)
	assert.Equal(t, uint32(common.VIF_DEVICE_TYPE_POD), e.InstanceType)
	assert.Equal(t, uint32(id), e.InstanceID)
	assert.Equal(t, name, e.InstanceName)

	em.ProduceByAdd([]*mysql.Pod{{Name: RandName()}, {Name: RandName()}})
	assert.Equal(t, 2, eq.Len())
}

func TestUpdatePod(t *testing.T) {
	ds := tool.NewDataSet()
	id := RandID()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(ds), "GetPodIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return id, true
	})
	defer monkey.Reset()

	name := RandName()
	monkey1 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(ds), "GetPodNameByID", func(_ *tool.DataSet, _ int) (string, bool) {
		return name, true
	})
	defer monkey1.Reset()

	podNodeID := RandID()
	monkey2 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(ds), "GetPodNodeIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return podNodeID, true
	})
	defer monkey2.Reset()

	podNodeName := RandName()
	monkey3 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(ds), "GetPodNodeNameByID", func(_ *tool.DataSet, _ int) (string, bool) {
		return podNodeName, true
	})
	defer monkey3.Reset()

	eq := NewEventQueue()
	em := NewPod(ds, eq)
	em.ProduceByUpdate(&cloudmodel.Pod{CreatedAt: time.Now()}, &diffbase.Pod{})
	assert.Equal(t, 1, eq.Len())
	e := eq.Get().(*eventapi.ResourceEvent)
	assert.Equal(t, eventapi.RESOURCE_EVENT_TYPE_RECREATE, e.Type)
	assert.Equal(t, fmt.Sprintf("%s,%s", podNodeName, podNodeName), e.Description)
}

func TestDeletePod(t *testing.T) {
	ds := tool.NewDataSet()
	id := RandID()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(ds), "GetPodIDByLcuuid", func(_ *tool.DataSet, _ string) (int, bool) {
		return id, true
	})
	defer monkey.Reset()

	name := RandName()
	monkey1 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(ds), "GetPodNameByID", func(_ *tool.DataSet, _ int) (string, bool) {
		return name, true
	})
	defer monkey1.Reset()

	eq := NewEventQueue()
	em := NewPod(ds, eq)
	em.ProduceByDelete([]string{RandLcuuid()})
	assert.Equal(t, 1, eq.Len())
	e := eq.Get().(*eventapi.ResourceEvent)
	assert.Equal(t, eventapi.RESOURCE_EVENT_TYPE_DELETE, e.Type)
	assert.Equal(t, uint32(id), e.InstanceID)
	assert.Equal(t, name, e.InstanceName)
}
