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
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (t *Tencent) getPeerConnections(region string) ([]model.PeerConnection, error) {
	log.Debug("get peer connections starting", logger.NewORGPrefix(t.orgID))
	var peerConnections []model.PeerConnection

	attrs := []string{"PeeringConnectionId", "PeeringConnectionName", "SourceVpcId", "DestinationVpcId"}

	resp, err := t.getResponse("vpc", "2017-03-12", "DescribeVpcPeeringConnections", region, "PeerConnectionSet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("peer connection request tencent api error: (%s)", err.Error(), logger.NewORGPrefix(t.orgID))
		return []model.PeerConnection{}, err
	}
	for _, pData := range resp {
		if !t.checkRequiredAttributes(pData, attrs) {
			continue
		}
		peerID := pData.Get("PeeringConnectionId").MustString()
		peerName := pData.Get("PeeringConnectionName").MustString()
		localVpcID := pData.Get("SourceVpcId").MustString()
		remoteVpcID := pData.Get("DestinationVpcId").MustString()

		peerConnections = append(peerConnections, model.PeerConnection{
			Lcuuid:             common.GetUUIDByOrgID(t.orgID, peerID),
			Name:               peerName,
			Label:              peerID,
			LocalVPCLcuuid:     common.GetUUIDByOrgID(t.orgID, localVpcID),
			RemoteVPCLcuuid:    common.GetUUIDByOrgID(t.orgID, remoteVpcID),
			LocalRegionLcuuid:  t.regionLcuuid,
			RemoteRegionLcuuid: t.regionLcuuid,
		})
	}
	log.Debug("get peer connections complete", logger.NewORGPrefix(t.orgID))
	return peerConnections, nil
}
