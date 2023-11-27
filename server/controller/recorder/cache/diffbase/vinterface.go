/**
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

package diffbase

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache/tool"
)

func (b *DataSet) AddVInterface(dbItem *mysql.VInterface, seq int, toolDataSet *tool.DataSet) {
	var networkLcuuid string
	if dbItem.NetworkID != 0 {
		networkLcuuid, _ = toolDataSet.GetNetworkLcuuidByID(dbItem.NetworkID)
	}
	b.VInterfaces[dbItem.Lcuuid] = &VInterface{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		Type:            dbItem.Type,
		VTapID:          dbItem.VtapID,
		NetnsID:         dbItem.NetnsID,
		TapMac:          dbItem.TapMac,
		NetworkLcuuid:   networkLcuuid,
		RegionLcuuid:    dbItem.Region,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, b.VInterfaces[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteVInterface(lcuuid string) {
	delete(b.VInterfaces, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, lcuuid))
}

type VInterface struct {
	DiffBase
	Name            string `json:"name"`
	Type            int    `json:"type"`
	TapMac          string `json:"tap_mac"`
	NetnsID         uint32 `json:"netns_id"`
	VTapID          uint32 `json:"vtap_id"`
	NetworkLcuuid   string `json:"network_lcuuid"`
	RegionLcuuid    string `json:"region_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (v *VInterface) Update(cloudItem *cloudmodel.VInterface) {
	v.Name = cloudItem.Name
	v.Type = cloudItem.Type
	v.TapMac = cloudItem.TapMac
	v.NetnsID = cloudItem.NetnsID
	v.VTapID = cloudItem.VTapID
	v.NetworkLcuuid = cloudItem.NetworkLcuuid
	v.RegionLcuuid = cloudItem.RegionLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_VINTERFACE_EN, v))
}
