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

package baidubce

import (
	"time"

	"github.com/baidubce/bce-sdk-go/services/vpc"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (b *BaiduBce) getPeerConnections(region model.Region, vpcIdToLcuuid map[string]string) ([]model.PeerConnection, error) {
	var retPeerConnections []model.PeerConnection

	log.Debug("get peer_connections starting")

	vpcClient, _ := vpc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	vpcClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	marker := ""
	args := &vpc.ListPeerConnsArgs{}
	results := make([]*vpc.ListPeerConnsResult, 0)
	for {
		args.Marker = marker
		startTime := time.Now()
		result, err := vpcClient.ListPeerConn(args)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		b.cloudStatsd.RefreshAPIMoniter("ListPeerConn", len(result.PeerConns), startTime)
		results = append(results, result)
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}

	b.debugger.WriteJson("ListPeerConn", " ", structToJson(results))
	for _, r := range results {
		for _, conn := range r.PeerConns {
			if conn.Role != "acceptor" {
				continue
			}
			localVPCLcuuid, ok := vpcIdToLcuuid[conn.LocalVpcId]
			if !ok {
				log.Debugf("peer_connection (%s) local_vpc_id (%s) not found", conn.PeerConnId, conn.LocalVpcId)
				continue
			}
			remoteVPCLcuuid, ok := vpcIdToLcuuid[conn.PeerVpcId]
			if !ok {
				log.Debugf("peer_connection (%s) remote_vpc_id (%s) not found", conn.PeerConnId, conn.PeerVpcId)
				continue
			}
			retPeerConnections = append(retPeerConnections, model.PeerConnection{
				Lcuuid:             common.GenerateUUID(conn.PeerConnId),
				Name:               conn.PeerConnId,
				Label:              conn.PeerConnId,
				LocalVPCLcuuid:     localVPCLcuuid,
				RemoteVPCLcuuid:    remoteVPCLcuuid,
				LocalRegionLcuuid:  region.Lcuuid,
				RemoteRegionLcuuid: region.Lcuuid,
			})
		}
	}

	log.Debug("get peer_connections complete")
	return retPeerConnections, nil
}
