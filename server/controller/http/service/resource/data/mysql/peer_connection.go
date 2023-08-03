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

package mysql

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type PeerConnection struct {
	DataProvider
	dataTool *peerConnectionToolData
}

func NewPeerConnection() *PeerConnection {
	dp := &PeerConnection{newDataProvider(ctrlrcommon.RESOURCE_TYPE_PEER_CONNECTION_EN), new(peerConnectionToolData)}
	dp.setGenerator(dp)
	return dp
}

func (v *PeerConnection) generate() (data []common.ResponseElem, err error) {
	err = v.dataTool.Init().Load()
	for _, item := range v.dataTool.peerConnections {
		data = append(data, v.generateOne(item))
	}
	return
}

func (v *PeerConnection) generateOne(item mysql.PeerConnection) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["DOMAIN_NAME"] = v.dataTool.domainLcuuidToName[item.Domain]
	d["LOCAL_REGION_NAME"] = v.dataTool.regionIDToName[item.LocalRegionID]
	d["REMOTE_REGION_NAME"] = v.dataTool.regionIDToName[item.RemoteRegionID]
	d["LOCAL_EPC_NAME"] = v.dataTool.vpcIDToName[item.LocalVPCID]
	d["REMOTE_EPC_NAME"] = v.dataTool.vpcIDToName[item.RemoteVPCID]

	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

type peerConnectionToolData struct {
	peerConnections []mysql.PeerConnection

	domainLcuuidToName map[string]string
	regionIDToName     map[int]string
	vpcIDToName        map[int]string
}

func (td *peerConnectionToolData) Init() *peerConnectionToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionIDToName = make(map[int]string)
	td.vpcIDToName = make(map[int]string)
	return td
}

func (td *peerConnectionToolData) Load() (err error) {
	td.peerConnections, err = UnscopedOrderFind[mysql.PeerConnection]("created_at DESC")
	if err != nil {
		return err
	}

	domains, err := Select[mysql.Domain]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}

	regions, err := Select[mysql.Region]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range regions {
		td.regionIDToName[item.ID] = item.Name
	}

	vpcs, err := Select[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	return nil
}
