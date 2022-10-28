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
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/bxcodec/faker/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/recorder/cache"
	"github.com/deepflowys/deepflow/server/libs/eventapi"
	"github.com/deepflowys/deepflow/server/libs/queue"
)

func RandID() int {
	rand.Seed(time.Now().UnixNano())
	time.Sleep(time.Millisecond)
	return rand.Intn(9999)
}

func RandLcuuid() string {
	return uuid.NewString()
}

func RandName() string {
	return uuid.NewString()[:7]
}

func NewEventQueue() *queue.OverwriteQueue {
	return queue.NewOverwriteQueue(
		"controller-to-ingester-resource_event", 1<<4,
		queue.OptionFlushIndicator(time.Second*3),
		queue.OptionRelease(func(p interface{}) { p.(*eventapi.ResourceEvent).Release() }))
}

func TestAddWANIP(t *testing.T) {
	ds := cache.NewToolDataSet()

	vifLcuuid := RandLcuuid()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&ds), "GetVInterfaceLcuuidByID", func(_ *cache.ToolDataSet, _ int) (string, bool) {
		return vifLcuuid, true
	})
	defer monkey.Reset()

	vmID := RandID()
	vmName := RandName()
	monkey1 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&ds), "GetDeviceInfoByVInterfaceLcuuid", func(_ *cache.ToolDataSet, _ string) (*cache.DeviceInfo, bool) {
		return &cache.DeviceInfo{ID: vmID, Name: vmName, Type: common.VIF_DEVICE_TYPE_VM}, true
	})
	defer monkey1.Reset()

	netID := RandID()
	netName := RandName()
	monkey2 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&ds), "GetNetworkInfoByVInterfaceLcuuid", func(_ *cache.ToolDataSet, _ string) (*cache.NetworkInfo, bool) {
		return &cache.NetworkInfo{ID: netID, Name: netName}, true
	})
	defer monkey2.Reset()

	ip := faker.IPv4()
	eq := NewEventQueue()
	wanIP := NewWANIP(ds, eq)
	wanIP.ProduceByAdd([]*mysql.WANIP{{VInterfaceID: RandID(), IP: ip}})
	assert.Equal(t, 1, eq.Len())
	e := eq.Get().(*eventapi.ResourceEvent)
	assert.Equal(t, fmt.Sprintf("%s-%s", netName, ip), e.Description)
	assert.Equal(t, vmName, e.ResourceName)
}

func TestDeleteWANIP(t *testing.T) {
	ds := cache.NewToolDataSet()

	vifID := RandID()
	vifLcuuid := RandLcuuid()
	monkey := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&ds), "GetVInterfaceLcuuidByID", func(_ *cache.ToolDataSet, _ int) (string, bool) {
		return vifLcuuid, true
	})
	defer monkey.Reset()

	podID := RandID()
	podName := RandName()
	monkey1 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&ds), "GetDeviceInfoByVInterfaceLcuuid", func(_ *cache.ToolDataSet, _ string) (*cache.DeviceInfo, bool) {
		return &cache.DeviceInfo{ID: podID, Name: podName, Type: common.VIF_DEVICE_TYPE_POD}, true
	})
	defer monkey1.Reset()

	netID := RandID()
	netName := RandName()
	monkey2 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&ds), "GetNetworkInfoByVInterfaceLcuuid", func(_ *cache.ToolDataSet, _ string) (*cache.NetworkInfo, bool) {
		return &cache.NetworkInfo{ID: netID, Name: netName}, true
	})
	defer monkey2.Reset()

	monkey3 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&ds), "GetVInterfaceIDByWANIPLcuuid", func(_ *cache.ToolDataSet, _ string) (int, bool) {
		return vifID, true
	})
	defer monkey3.Reset()

	monkey4 := gomonkey.ApplyPrivateMethod(reflect.TypeOf(&ds), "GetWANIPByLcuuid", func(_ *cache.ToolDataSet, _ string) (string, bool) {
		return faker.IPv6(), true
	})
	defer monkey4.Reset()

	eq := NewEventQueue()
	wanIP := NewWANIP(ds, eq)
	wanIP.ProduceByDelete([]string{RandLcuuid()})
	assert.Equal(t, 1, eq.Len())
	e := eq.Get().(*eventapi.ResourceEvent)
	assert.Equal(t, eventapi.RESOURCE_EVENT_TYPE_REMOVE_IP, e.Type)
	assert.Equal(t, uint32(common.VIF_DEVICE_TYPE_POD), e.ResourceType)
	assert.Equal(t, uint32(podID), e.ResourceID)
}
