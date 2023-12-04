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

func (b *DataSet) AddNetwork(dbItem *mysql.Network, seq int, toolDataSet *tool.DataSet) {
	vpcLcuuid, _ := toolDataSet.GetVPCLcuuidByID(dbItem.VPCID)
	b.Networks[dbItem.Lcuuid] = &Network{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:            dbItem.Name,
		Label:           dbItem.Label,
		TunnelID:        dbItem.TunnelID,
		NetType:         dbItem.NetType,
		SegmentationID:  dbItem.SegmentationID,
		VPCLcuuid:       vpcLcuuid,
		RegionLcuuid:    dbItem.Region,
		AZLcuuid:        dbItem.AZ,
		SubDomainLcuuid: dbItem.SubDomain,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, b.Networks[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteNetwork(lcuuid string) {
	delete(b.Networks, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, lcuuid))
}

type Network struct {
	DiffBase
	Name            string `json:"name"`
	Label           string `json:"label"`
	TunnelID        int    `json:"tunnel_id"`
	NetType         int    `json:"net_type"`
	SegmentationID  int    `json:"segmentation_id"`
	VPCLcuuid       string `json:"vpc_lcuuid"`
	RegionLcuuid    string `json:"region_lcuuid"`
	AZLcuuid        string `json:"az_lcuuid"`
	SubDomainLcuuid string `json:"sub_domain_lcuuid"`
}

func (n *Network) Update(cloudItem *cloudmodel.Network) {
	n.Name = cloudItem.Name
	n.Label = cloudItem.Label
	n.TunnelID = cloudItem.TunnelID
	n.NetType = cloudItem.NetType
	n.SegmentationID = cloudItem.SegmentationID
	n.VPCLcuuid = cloudItem.VPCLcuuid
	n.RegionLcuuid = cloudItem.RegionLcuuid
	n.AZLcuuid = cloudItem.AZLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_NETWORK_EN, n))
}
