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

package tencent

import (
	"github.com/deckarep/golang-set"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/satori/go.uuid"
)

func (t *Tencent) getPeerConnections(region tencentRegion, peerConnections []model.PeerConnection) ([]model.PeerConnection, error) {
	log.Debug("get peer connections starting")
	var pConnections []model.PeerConnection
	peerConnectionLcuuids := mapset.NewSet()
	for _, p := range peerConnections {
		peerConnectionLcuuids.Add(p.Lcuuid)
	}

	attrs := []string{"VpcPeerConnectionId", "VpcPeerConnectionName", "VpcId", "PeerVpcId"}

	resp, err := t.getResponse("bmvpc", "2018-06-25", "DescribeVpcPeerConnections", region.name, "VpcPeerConnectionSet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("peer connection request tencent api error: (%s)", err.Error())
		return []model.PeerConnection{}, err
	}
	for _, pData := range resp {
		if !t.checkRequiredAttributes(pData, attrs) {
			continue
		}
		peerID := pData.Get("VpcPeerConnectionId").MustString()
		peerLcuuid := common.GetUUID(peerID, uuid.Nil)
		if peerConnectionLcuuids.Contains(peerLcuuid) {
			continue
		}

		peerName := pData.Get("VpcPeerConnectionName").MustString()
		localVpcID := pData.Get("VpcId").MustString()
		remoteVpcID := pData.Get("PeerVpcId").MustString()
		localRegionLcuuid := t.vpcIDToRegionLcuuid[localVpcID]
		remoteRegionLcuuid := t.vpcIDToRegionLcuuid[remoteVpcID]
		if localRegionLcuuid == "" || remoteRegionLcuuid == "" {
			log.Infof("peer connection (%s) region not found", peerName)
			continue
		}

		peerConnections = append(peerConnections, model.PeerConnection{
			Lcuuid:             peerLcuuid,
			Name:               peerName,
			Label:              peerID,
			LocalVPCLcuuid:     common.GetUUID(localVpcID, uuid.Nil),
			RemoteVPCLcuuid:    common.GetUUID(remoteVpcID, uuid.Nil),
			LocalRegionLcuuid:  localRegionLcuuid,
			RemoteRegionLcuuid: remoteRegionLcuuid,
		})
	}
	log.Debug("get peer connections complete")
	return pConnections, nil
}
