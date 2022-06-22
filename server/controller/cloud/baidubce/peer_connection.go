package baidubce

import (
	"github.com/baidubce/bce-sdk-go/services/vpc"

	"server/controller/cloud/model"
	"server/controller/common"
)

func (b *BaiduBce) getPeerConnections(region model.Region, vpcIdToLcuuid map[string]string) ([]model.PeerConnection, error) {
	var retPeerConnections []model.PeerConnection

	log.Debug("get peer_connections starting")

	vpcClient, _ := vpc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	marker := ""
	args := &vpc.ListPeerConnsArgs{}
	results := make([]*vpc.ListPeerConnsResult, 0)
	for {
		args.Marker = marker
		result, err := vpcClient.ListPeerConn(args)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		results = append(results, result)
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}

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
