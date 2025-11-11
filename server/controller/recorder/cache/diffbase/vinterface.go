/**
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

package diffbase

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	mysqlmodel "github.com/deepflowio/deepflow/server/controller/db/metadb/model"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

func (b *DataSet) AddVInterface(dbItem *mysqlmodel.VInterface, seq int, toolDataSet *tool.DataSet) {
	var networkLcuuid string
	if dbItem.NetworkID != 0 {
		networkLcuuid, _ = toolDataSet.GetNetworkLcuuidByID(dbItem.NetworkID)
	}
	var deviceLcuuid string
	if dbItem.DeviceID != 0 {
		deviceLcuuid, _ = toolDataSet.GetDeviceLcuuidByID(dbItem.DeviceType, dbItem.DeviceID)
	}
	var vpcID int
	if dbItem.DeviceType != ctrlrcommon.VIF_DEVICE_TYPE_HOST {
		vpcID, _ = toolDataSet.GetDeviceVPCIDByID(dbItem.DeviceType, dbItem.DeviceID)
	}
	if vpcID == 0 {
		vpcID, _ = toolDataSet.GetNetworkVPCIDByID(dbItem.NetworkID)
	}
	b.VInterfaces[dbItem.Lcuuid] = &VInterface{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		Type:            dbItem.Type,
		VtapID:          dbItem.VtapID,
		NetnsID:         dbItem.NetnsID,
		TapMac:          dbItem.TapMac,
		VPCID:           dbItem.VPCID,
		DeviceType:      dbItem.DeviceType,
		DeviceLcuuid:    deviceLcuuid,
		NetworkLcuuid:   networkLcuuid,
		RegionLcuuid:    dbItem.Region,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, b.VInterfaces[dbItem.Lcuuid]), b.metadata.LogPrefixes)
}

func (b *DataSet) DeleteVInterface(lcuuid string) {
	delete(b.VInterfaces, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, lcuuid), b.metadata.LogPrefixes)
}

type VInterface struct {
	DiffBase
	Name            string `json:"name"`
	Type            int    `json:"type"`
	TapMac          string `json:"tap_mac"`
	NetnsID         uint32 `json:"netns_id"`
	VtapID          uint32 `json:"vtap_id"`
	VPCID           int    `json:"vpc_id"`
	DeviceType      int    `json:"device_type"`
	DeviceLcuuid    string `json:"device_lcuuid"`
	NetworkLcuuid   string `json:"network_lcuuid"`
	RegionLcuuid    string `json:"region_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (v *VInterface) Update(cloudItem *cloudmodel.VInterface) {
	v.Name = cloudItem.Name
	v.Type = cloudItem.Type
	v.TapMac = cloudItem.TapMac
	v.NetnsID = cloudItem.NetnsID
	v.VtapID = cloudItem.VTapID
	v.VPCID = cloudItem.VPCID
	v.DeviceLcuuid = cloudItem.DeviceLcuuid
	v.NetworkLcuuid = cloudItem.NetworkLcuuid
	v.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, v))
}
