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

package cache

import (
	"math/rand"
	"time"

	"github.com/bxcodec/faker/v3"
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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

func (t *SuiteTest) TestAddNetworkInTDS() {
	id := RandID()
	name := RandName()
	dbItem := &mysql.Network{Base: mysql.Base{ID: id, Lcuuid: RandLcuuid()}, Name: name}
	ds := NewToolDataSet()
	ds.addNetwork(dbItem)
	assert.Equal(t.T(), name, ds.networkIDToName[id])
}

func (t *SuiteTest) TestUpdateNetworkInTDS() {
	id := RandID()
	lcuuid := RandLcuuid()
	ds := NewToolDataSet()
	ds.networkIDToName[id] = RandName()
	ds.networkLcuuidToID[lcuuid] = id
	newName := RandName()
	cloudItem := &cloudmodel.Network{Name: newName, Lcuuid: lcuuid}
	ds.updateNetwork(cloudItem)
	assert.Equal(t.T(), newName, ds.networkIDToName[id])
}

func (t *SuiteTest) TestDeleteNetworkInTDS() {
	id := RandID()
	lcuuid := RandLcuuid()
	ds := NewToolDataSet()
	ds.networkIDToName[id] = RandName()
	ds.networkLcuuidToID[lcuuid] = id
	ds.deleteNetwork(lcuuid)
	_, ok := ds.networkIDToName[id]
	assert.Equal(t.T(), false, ok)
}

func (t *SuiteTest) TestAddWANIPInTDS() {
	lcuuid := RandLcuuid()
	vifID := RandID()
	ip := faker.IPv4()
	dbItem := &mysql.WANIP{Base: mysql.Base{ID: RandID(), Lcuuid: lcuuid}, VInterfaceID: vifID, IP: ip}
	ds := NewToolDataSet()
	ds.addWANIP(dbItem)
	assert.Equal(t.T(), ip, ds.wanIPLcuuidToIP[lcuuid])
	assert.Equal(t.T(), vifID, ds.wanIPLcuuidToVInterfaceID[lcuuid])
}

func (t *SuiteTest) TestDeleteWANIPInTDS() {
	lcuuid := RandLcuuid()
	ds := NewToolDataSet()
	ds.wanIPLcuuidToIP[lcuuid] = faker.IPv4()
	ds.wanIPLcuuidToVInterfaceID[lcuuid] = RandID()
	ds.deleteWANIP(lcuuid)
	_, ok := ds.wanIPLcuuidToIP[lcuuid]
	assert.Equal(t.T(), false, ok)
	_, ok = ds.wanIPLcuuidToVInterfaceID[lcuuid]
	assert.Equal(t.T(), false, ok)
}

func (t *SuiteTest) TestGetNetworkNameByID() {
	id := RandID()
	name := RandName()
	ds := NewToolDataSet()
	ds.networkIDToName[id] = name
	rname, _ := ds.GetNetworkNameByID(id)
	assert.Equal(t.T(), name, rname)

	id2 := RandID()
	name2 := RandName()
	dbItem := &mysql.Network{Base: mysql.Base{ID: id2, Lcuuid: RandLcuuid()}, Name: name2}
	mysql.Db.Create(&dbItem)
	rname2, _ := ds.GetNetworkNameByID(id2)
	assert.Equal(t.T(), name2, rname2)
}

func (t *SuiteTest) TestGetVInterfaceLcuuidByID() {
	id := RandID()
	lcuuid := RandLcuuid()
	ds := NewToolDataSet()
	ds.vinterfaceIDToLcuuid[id] = lcuuid
	rlcuuid, _ := ds.GetVInterfaceLcuuidByID(id)
	assert.Equal(t.T(), lcuuid, rlcuuid)

	id2 := RandID()
	lcuuid2 := RandLcuuid()
	dbItem := &mysql.VInterface{Base: mysql.Base{ID: id2, Lcuuid: lcuuid2}}
	mysql.Db.Create(&dbItem)
	rlcuuid2, _ := ds.GetVInterfaceLcuuidByID(id2)
	assert.Equal(t.T(), lcuuid2, rlcuuid2)
}

func (t *SuiteTest) TestGetVInterfaceIDByWANIPLcuuid() {
	lcuuid := RandLcuuid()
	vifID := RandID()
	ds := NewToolDataSet()
	ds.wanIPLcuuidToVInterfaceID[lcuuid] = vifID
	rvifID, _ := ds.GetVInterfaceIDByWANIPLcuuid(lcuuid)
	assert.Equal(t.T(), vifID, rvifID)

	vifID2 := RandID()
	lcuuid2 := RandLcuuid()
	dbItem := &mysql.WANIP{Base: mysql.Base{Lcuuid: lcuuid2}, VInterfaceID: vifID2}
	mysql.Db.Create(&dbItem)
	rvifID2, _ := ds.GetVInterfaceIDByWANIPLcuuid(lcuuid2)
	assert.Equal(t.T(), vifID2, rvifID2)
}

func (t *SuiteTest) TestGetWANIPByLcuuid() {
	ip := faker.IPv4()
	lcuuid := RandLcuuid()
	ds := NewToolDataSet()
	ds.wanIPLcuuidToIP[lcuuid] = ip
	rip, _ := ds.GetWANIPByLcuuid(lcuuid)
	assert.Equal(t.T(), ip, rip)

	ip2 := faker.IPv4()
	lcuuid2 := RandLcuuid()
	dbItem := &mysql.WANIP{Base: mysql.Base{Lcuuid: lcuuid2}, IP: ip2}
	mysql.Db.Create(&dbItem)
	rip2, _ := ds.GetWANIPByLcuuid(lcuuid2)
	assert.Equal(t.T(), ip2, rip2)
}
