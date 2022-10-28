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
	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func RandID() int {
	rand.Seed(time.Now().UnixNano())
	time.Sleep(time.Millisecond)
	return rand.Intn(9999)
}

func FormatLcuuid(lcuuid string) string {
	if lcuuid == "" {
		return uuid.NewString()
	}
	return lcuuid
}

func RandName() string {
	return uuid.NewString()[:7]
}

func (t *SuiteTest) TestAddVMInTDS() {
	id := RandID()
	name := RandName()
	dbItem := &mysql.VM{Base: mysql.Base{ID: id, Lcuuid: FormatLcuuid("")}, Name: name}
	ds := NewToolDataSet()
	ds.addVM(dbItem)
	assert.Equal(t.T(), name, ds.VMIDToName[id])
}

func (t *SuiteTest) TestUpdateVMInTDS() {
	id := RandID()
	lcuuid := FormatLcuuid("")
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
	lcuuid := FormatLcuuid("")
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
	dbItem := &mysql.Network{Base: mysql.Base{ID: id, Lcuuid: FormatLcuuid("")}, Name: name}
	ds := NewToolDataSet()
	ds.addNetwork(dbItem)
	assert.Equal(t.T(), name, ds.NetworkIDToName[id])
}

func (t *SuiteTest) TestUpdateNetworkInTDS() {
	id := RandID()
	lcuuid := FormatLcuuid("")
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
	lcuuid := FormatLcuuid("")
	ds := NewToolDataSet()
	ds.NetworkIDToName[id] = RandName()
	ds.NetworkLcuuidToID[lcuuid] = id
	ds.deleteNetwork(lcuuid)
	_, ok := ds.NetworkIDToName[id]
	assert.Equal(t.T(), false, ok)
}

func (t *SuiteTest) TestAddVInterfaceInTDS() {
	id := RandID()
	lcuuid := FormatLcuuid("")
	networkID := RandID()
	vmID := RandID()
	dbItem := &mysql.VInterface{Base: mysql.Base{ID: id, Lcuuid: lcuuid}, DeviceType: common.VIF_DEVICE_TYPE_VM, DeviceID: vmID, NetworkID: networkID}
	ds := NewToolDataSet()
	ds.NetworkIDToName[networkID] = RandName()
	ds.VMIDToName[vmID] = RandName()
	ds.addVInterface(dbItem)
	assert.Equal(t.T(), networkID, ds.VInterfaceLcuuidToNetworkInfo[lcuuid].ID)
	assert.Equal(t.T(), vmID, ds.VInterfaceLcuuidToDeviceInfo[lcuuid].ID)
	assert.Equal(t.T(), common.VIF_DEVICE_TYPE_VM, ds.VInterfaceLcuuidToDeviceInfo[lcuuid].Type)
}

func (t *SuiteTest) TestDeleteVInterfaceInTDS() {
	id := RandID()
	lcuuid := FormatLcuuid("")
	ds := NewToolDataSet()
	ds.VInterfaceLcuuidToID[lcuuid] = id
	ds.VInterfaceLcuuidToDeviceInfo[lcuuid] = &DeviceInfo{ID: RandID()}
	ds.VInterfaceLcuuidToNetworkInfo[lcuuid] = &NetworkInfo{ID: RandID()}
	ds.deleteVInterface(lcuuid)
	_, ok := ds.VInterfaceLcuuidToNetworkInfo[lcuuid]
	assert.Equal(t.T(), false, ok)
	_, ok = ds.VInterfaceLcuuidToDeviceInfo[lcuuid]
	assert.Equal(t.T(), false, ok)
}

func (t *SuiteTest) TestAddWANIPInTDS() {
	lcuuid := FormatLcuuid("")
	vifID := RandID()
	ip := faker.IPv4()
	dbItem := &mysql.WANIP{Base: mysql.Base{ID: RandID(), Lcuuid: lcuuid}, VInterfaceID: vifID, IP: ip}
	ds := NewToolDataSet()
	ds.addWANIP(dbItem)
	assert.Equal(t.T(), ip, ds.WANIPLcuuidToIP[lcuuid])
	assert.Equal(t.T(), vifID, ds.WANIPLcuuidToVInterfaceID[lcuuid])
}

func (t *SuiteTest) TestDeleteWANIPInTDS() {
	lcuuid := FormatLcuuid("")
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
	dbItem := &mysql.VM{Base: mysql.Base{ID: id2, Lcuuid: FormatLcuuid("")}, Name: name2}
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
	log.Info(id)
	log.Info(ds.NetworkIDToName)

	id2 := RandID()
	name2 := RandName()
	dbItem := &mysql.Network{Base: mysql.Base{ID: id2, Lcuuid: FormatLcuuid("")}, Name: name2}
	mysql.Db.Create(&dbItem)
	log.Info(id2)
	log.Info(ds.NetworkIDToName)
	rname2, _ := ds.GetNetworkNameByID(id2)
	assert.Equal(t.T(), name2, rname2)
}

func (t *SuiteTest) TestGetDeviceInfoByVInterfaceLcuuid() {
	lcuuid := FormatLcuuid("")
	vmID := RandID()
	info := &DeviceInfo{Type: common.VIF_DEVICE_TYPE_VM, ID: vmID}
	ds := NewToolDataSet()
	ds.VInterfaceLcuuidToDeviceInfo[lcuuid] = info
	rinfo, _ := ds.GetDeviceInfoByVInterfaceLcuuid(lcuuid)
	assert.Equal(t.T(), vmID, rinfo.ID)

	lcuuid2 := FormatLcuuid("")
	vmID2 := RandID()
	vmName2 := RandName()
	ds.VMIDToName[vmID2] = vmName2
	dbItem := &mysql.VInterface{Base: mysql.Base{Lcuuid: lcuuid2}, DeviceType: common.VIF_DEVICE_TYPE_VM, DeviceID: vmID2}
	mysql.Db.Create(&dbItem)
	rinfo2, _ := ds.GetDeviceInfoByVInterfaceLcuuid(lcuuid2)
	assert.Equal(t.T(), vmName2, rinfo2.Name)
}

func (t *SuiteTest) TestGetNetworkInfoByVInterfaceLcuuid() {
	lcuuid := FormatLcuuid("")
	netID := RandID()
	info := &NetworkInfo{ID: netID}
	ds := NewToolDataSet()
	ds.VInterfaceLcuuidToNetworkInfo[lcuuid] = info
	rinfo, _ := ds.GetNetworkInfoByVInterfaceLcuuid(lcuuid)
	assert.Equal(t.T(), netID, rinfo.ID)

	lcuuid2 := FormatLcuuid("")
	netID2 := RandID()
	netName2 := RandName()
	ds.NetworkIDToName[netID2] = netName2
	dbItem := &mysql.VInterface{Base: mysql.Base{Lcuuid: lcuuid2}, NetworkID: netID2}
	mysql.Db.Create(&dbItem)
	rinfo2, _ := ds.GetNetworkInfoByVInterfaceLcuuid(lcuuid2)
	assert.Equal(t.T(), netName2, rinfo2.Name)
}

func (t *SuiteTest) TestGetVInterfaceLcuuidByID() {
	id := RandID()
	lcuuid := FormatLcuuid("")
	ds := NewToolDataSet()
	ds.VInterfaceIDToLcuuid[id] = lcuuid
	rlcuuid, _ := ds.GetVInterfaceLcuuidByID(id)
	assert.Equal(t.T(), lcuuid, rlcuuid)

	id2 := RandID()
	lcuuid2 := FormatLcuuid("")
	dbItem := &mysql.VInterface{Base: mysql.Base{ID: id2, Lcuuid: lcuuid2}}
	mysql.Db.Create(&dbItem)
	rlcuuid2, _ := ds.GetVInterfaceLcuuidByID(id2)
	assert.Equal(t.T(), lcuuid2, rlcuuid2)
}

func (t *SuiteTest) TestGetVInterfaceIDByWANIPLcuuid() {
	lcuuid := FormatLcuuid("")
	vifID := RandID()
	ds := NewToolDataSet()
	ds.WANIPLcuuidToVInterfaceID[lcuuid] = vifID
	rvifID, _ := ds.GetVInterfaceIDByWANIPLcuuid(lcuuid)
	assert.Equal(t.T(), vifID, rvifID)

	vifID2 := RandID()
	lcuuid2 := FormatLcuuid("")
	dbItem := &mysql.WANIP{Base: mysql.Base{Lcuuid: lcuuid2}, VInterfaceID: vifID2}
	mysql.Db.Create(&dbItem)
	rvifID2, _ := ds.GetVInterfaceIDByWANIPLcuuid(lcuuid2)
	assert.Equal(t.T(), vifID2, rvifID2)
}

func (t *SuiteTest) TestGetWANIPByLcuuid() {
	ip := faker.IPv4()
	lcuuid := FormatLcuuid("")
	ds := NewToolDataSet()
	ds.WANIPLcuuidToIP[lcuuid] = ip
	rip, _ := ds.GetWANIPByLcuuid(lcuuid)
	assert.Equal(t.T(), ip, rip)

	ip2 := faker.IPv4()
	lcuuid2 := FormatLcuuid("")
	dbItem := &mysql.WANIP{Base: mysql.Base{Lcuuid: lcuuid2}, IP: ip2}
	mysql.Db.Create(&dbItem)
	rip2, _ := ds.GetWANIPByLcuuid(lcuuid2)
	assert.Equal(t.T(), ip2, rip2)
}
