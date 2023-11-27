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

func (b *DataSet) AddPeerConnection(dbItem *mysql.PeerConnection, seq int, toolDataSet *tool.DataSet) {
	remoteRegionLcuuid, _ := toolDataSet.GetRegionLcuuidByID(dbItem.RemoteRegionID)
	localRegionLcuuid, _ := toolDataSet.GetRegionLcuuidByID(dbItem.LocalRegionID)
	b.PeerConnections[dbItem.Lcuuid] = &PeerConnection{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Name:               dbItem.Name,
		RemoteRegionLcuuid: remoteRegionLcuuid,
		LocalRegionLcuuid:  localRegionLcuuid,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN, b.PeerConnections[dbItem.Lcuuid]))
}

func (b *DataSet) DeletePeerConnection(lcuuid string) {
	delete(b.PeerConnections, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN, lcuuid))
}

type PeerConnection struct {
	DiffBase
	Name               string `json:"name"`
	RemoteRegionLcuuid string `json:"remote_region_lcuuid"`
	LocalRegionLcuuid  string `json:"local_region_lcuuid"`
}

func (p *PeerConnection) Update(cloudItem *cloudmodel.PeerConnection) {
	p.Name = cloudItem.Name
	p.RemoteRegionLcuuid = cloudItem.RemoteRegionLcuuid
	p.LocalRegionLcuuid = cloudItem.LocalRegionLcuuid
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN, p))
}
