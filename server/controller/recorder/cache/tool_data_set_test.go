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
	cloudmodel "github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
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

func (t *SuiteTest) TestAddVMInTDS() {
	id := RandID()
	name := RandName()
	dbItem := &mysql.VM{Base: mysql.Base{ID: id, Lcuuid: RandLcuuid()}, Name: name}
	ds := NewToolDataSet()
	ds.addVM(dbItem)
	assert.Equal(t.T(), name, ds.VMIDToName[id])
}

func (t *SuiteTest) TestUpdateVMInTDS() {
	id := RandID()
	lcuuid := RandLcuuid()
	ds := NewToolDataSet()
	ds.VMIDToName[id] = RandName()
	ds.VMLcuuidToID[lcuuid] = id
	newName := RandName()
	cloudItem := &cloudmodel.VM{Name: newName, Lcuuid: lcuuid}
	ds.updateVM(cloudItem)
	assert.Equal(t.T(), newName, ds.VMIDToName[id])
}

func (t *SuiteTest) TestDeleteVMInTDS() {
	id := RandID()
	lcuuid := RandLcuuid()
	ds := NewToolDataSet()
	ds.VMIDToName[id] = RandName()
	ds.VMLcuuidToID[lcuuid] = id
	ds.deleteVM(lcuuid)
	_, ok := ds.VMIDToName[id]
	assert.Equal(t.T(), false, ok)
}

func (t *SuiteTest) TestAddNetworkInTDS() {
	id := RandID()
	name := RandName()
	dbItem := &mysql.Network{Base: mysql.Base{ID: id, Lcuuid: RandLcuuid()}, Name: name}
	ds := NewToolDataSet()
	ds.addNetwork(dbItem)
	assert.Equal(t.T(), name, ds.NetworkIDToName[id])
}

func (t *SuiteTest) TestUpdateNetworkInTDS() {
	id := RandID()
	lcuuid := RandLcuuid()
	ds := NewToolDataSet()
	ds.NetworkIDToName[id] = RandName()
	ds.NetworkLcuuidToID[lcuuid] = id
	newName := RandName()
	cloudItem := &cloudmodel.Network{Name: newName, Lcuuid: lcuuid}
	ds.updateNetwork(cloudItem)
	assert.Equal(t.T(), newName, ds.NetworkIDToName[id])
}

func (t *SuiteTest) TestDeleteNetworkInTDS() {
	id := RandID()
	lcuuid := RandLcuuid()
	ds := NewToolDataSet()
	ds.NetworkIDToName[id] = RandName()
	ds.NetworkLcuuidToID[lcuuid] = id
	ds.deleteNetwork(lcuuid)
	_, ok := ds.NetworkIDToName[id]
	assert.Equal(t.T(), false, ok)
}

func (t *SuiteTest) TestAddWANIPInTDS() {
	lcuuid := RandLcuuid()
	vifID := RandID()
	ip := faker.IPv4()
	dbItem := &mysql.WANIP{Base: mysql.Base{ID: RandID(), Lcuuid: lcuuid}, VInterfaceID: vifID, IP: ip}
	ds := NewToolDataSet()
	ds.addWANIP(dbItem)
	assert.Equal(t.T(), ip, ds.WANIPLcuuidToIP[lcuuid])
	assert.Equal(t.T(), vifID, ds.WANIPLcuuidToVInterfaceID[lcuuid])
}

func (t *SuiteTest) TestDeleteWANIPInTDS() {
	lcuuid := RandLcuuid()
	ds := NewToolDataSet()
	ds.WANIPLcuuidToIP[lcuuid] = faker.IPv4()
	ds.WANIPLcuuidToVInterfaceID[lcuuid] = RandID()
	ds.deleteWANIP(lcuuid)
	_, ok := ds.WANIPLcuuidToIP[lcuuid]
	assert.Equal(t.T(), false, ok)
	_, ok = ds.WANIPLcuuidToVInterfaceID[lcuuid]
	assert.Equal(t.T(), false, ok)
}

func (t *SuiteTest) TestGetVMNameByID() {
	id := RandID()
	name := RandName()
	ds := NewToolDataSet()
	ds.VMIDToName[id] = name
	rname, _ := ds.GetVMNameByID(id)
	assert.Equal(t.T(), name, rname)

	id2 := RandID()
	name2 := RandName()
	dbItem := &mysql.VM{Base: mysql.Base{ID: id2, Lcuuid: RandLcuuid()}, Name: name2}
	mysql.Db.Create(&dbItem)
	rname2, _ := ds.GetVMNameByID(id2)
	assert.Equal(t.T(), name2, rname2)
}

func (t *SuiteTest) TestGetNetworkNameByID() {
	id := RandID()
	name := RandName()
	ds := NewToolDataSet()
	ds.NetworkIDToName[id] = name
	rname, _ := ds.GetNetworkNameByID(id)
	assert.Equal(t.T(), name, rname)

	id2 := RandID()
	name2 := RandName()
	dbItem := &mysql.Network{Base: mysql.Base{ID: id2, Lcuuid: RandLcuuid()}, Name: name2}
	mysql.Db.Create(&dbItem)
	rname2, _ := ds.GetNetworkNameByID(id2)
	assert.Equal(t.T(), name2, rname2)
}

func (t *SuiteTest) TestGetPodNodeNameByID() {
	id := RandID()
	name := RandName()
	ds := NewToolDataSet()
	ds.PodNodeIDToName[id] = name
	rname, _ := ds.GetPodNodeNameByID(id)
	assert.Equal(t.T(), name, rname)

	id2 := RandID()
	name2 := RandName()
	dbItem := &mysql.PodNode{Base: mysql.Base{ID: id2, Lcuuid: RandLcuuid()}, Name: name2}
	mysql.Db.Create(&dbItem)
	rname2, _ := ds.GetPodNodeNameByID(id2)
	assert.Equal(t.T(), name2, rname2)
}

func (t *SuiteTest) TestGetPodServiceNameByID() {
	id := RandID()
	name := RandName()
	ds := NewToolDataSet()
	ds.PodServiceIDToName[id] = name
	rname, _ := ds.GetPodServiceNameByID(id)
	assert.Equal(t.T(), name, rname)

	id2 := RandID()
	name2 := RandName()
	dbItem := &mysql.PodService{Base: mysql.Base{ID: id2, Lcuuid: RandLcuuid()}, Name: name2}
	mysql.Db.Create(&dbItem)
	rname2, _ := ds.GetPodServiceNameByID(id2)
	assert.Equal(t.T(), name2, rname2)
}

func (t *SuiteTest) TestGetPodNameByID() {
	id := RandID()
	name := RandName()
	ds := NewToolDataSet()
	ds.PodIDToName[id] = name
	rname, _ := ds.GetPodNameByID(id)
	assert.Equal(t.T(), name, rname)

	id2 := RandID()
	name2 := RandName()
	dbItem := &mysql.Pod{Base: mysql.Base{ID: id2, Lcuuid: RandLcuuid()}, Name: name2}
	mysql.Db.Create(&dbItem)
	rname2, _ := ds.GetPodNameByID(id2)
	assert.Equal(t.T(), name2, rname2)
}

func (t *SuiteTest) TestGetVInterfaceLcuuidByID() {
	id := RandID()
	lcuuid := RandLcuuid()
	ds := NewToolDataSet()
	ds.VInterfaceIDToLcuuid[id] = lcuuid
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
	ds.WANIPLcuuidToVInterfaceID[lcuuid] = vifID
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
	ds.WANIPLcuuidToIP[lcuuid] = ip
	rip, _ := ds.GetWANIPByLcuuid(lcuuid)
	assert.Equal(t.T(), ip, rip)

	ip2 := faker.IPv4()
	lcuuid2 := RandLcuuid()
	dbItem := &mysql.WANIP{Base: mysql.Base{Lcuuid: lcuuid2}, IP: ip2}
	mysql.Db.Create(&dbItem)
	rip2, _ := ds.GetWANIPByLcuuid(lcuuid2)
	assert.Equal(t.T(), ip2, rip2)
}
