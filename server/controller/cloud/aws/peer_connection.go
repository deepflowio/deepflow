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

package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (a *Aws) getPeerConnections(client *ec2.Client) ([]model.PeerConnection, error) {
	log.Debug("get peer connections starting", logger.NewORGPrefix(a.orgID))
	var peerConnections []model.PeerConnection

	var retPeerConnections []types.VpcPeeringConnection
	var nextToken string
	var maxResults int32 = 100
	for {
		var input *ec2.DescribeVpcPeeringConnectionsInput
		if nextToken == "" {
			input = &ec2.DescribeVpcPeeringConnectionsInput{MaxResults: &maxResults}
		} else {
			input = &ec2.DescribeVpcPeeringConnectionsInput{MaxResults: &maxResults, NextToken: &nextToken}
		}
		result, err := client.DescribeVpcPeeringConnections(context.TODO(), input)
		if err != nil {
			log.Errorf("peer connection request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
			return []model.PeerConnection{}, err
		}
		retPeerConnections = append(retPeerConnections, result.VpcPeeringConnections...)
		if result.NextToken == nil {
			break
		}
		nextToken = *result.NextToken
	}

	for _, pData := range retPeerConnections {
		peerConnectionID := a.getStringPointerValue(pData.VpcPeeringConnectionId)
		peerConnectionName := a.getResultTagName(pData.Tags)
		if peerConnectionName == "" {
			peerConnectionName = peerConnectionID
		}
		if pData.AccepterVpcInfo == nil || pData.RequesterVpcInfo == nil {
			log.Debug("accepter or requester vpc info is nil", logger.NewORGPrefix(a.orgID))
			continue
		}
		if pData.Status.Code != types.VpcPeeringConnectionStateReasonCodeActive {
			log.Infof("peer connections (%s) status (%s) invalid", peerConnectionName, pData.Status.Code, logger.NewORGPrefix(a.orgID))
			continue
		}
		peerConnections = append(peerConnections, model.PeerConnection{
			Lcuuid:             common.GetUUIDByOrgID(a.orgID, peerConnectionID),
			Name:               peerConnectionName,
			Label:              peerConnectionID,
			RemoteVPCLcuuid:    common.GetUUIDByOrgID(a.orgID, a.getStringPointerValue(pData.AccepterVpcInfo.VpcId)),
			LocalVPCLcuuid:     common.GetUUIDByOrgID(a.orgID, a.getStringPointerValue(pData.RequesterVpcInfo.VpcId)),
			RemoteRegionLcuuid: a.regionLcuuid,
			LocalRegionLcuuid:  a.regionLcuuid,
		})
	}
	log.Debug("get peer connections complete", logger.NewORGPrefix(a.orgID))
	return peerConnections, nil
}
