package baidubce

import (
	"github.com/baidubce/bce-sdk-go/services/vpc"

	"server/controller/cloud/model"
	"server/controller/common"
)

func (b *BaiduBce) getNetworks(
	region model.Region, zoneNameToAZLcuuid map[string]string, vpcIdToLcuuid map[string]string,
) ([]model.Network, []model.Subnet, map[string]string, error) {
	var retNetworks []model.Network
	var retSubnets []model.Subnet
	var networkIdToLcuuid map[string]string

	log.Debug("get networks starting")

	vpcClient, _ := vpc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	marker := ""
	args := &vpc.ListSubnetArgs{}
	results := make([]*vpc.ListSubnetResult, 0)
	for {
		args.Marker = marker
		result, err := vpcClient.ListSubnets(args)
		if err != nil {
			log.Error(err)
			return nil, nil, nil, err
		}
		results = append(results, result)
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}

	networkIdToLcuuid = make(map[string]string)
	for _, r := range results {
		for _, subnet := range r.Subnets {
			azLcuuid, ok := zoneNameToAZLcuuid[subnet.ZoneName]
			if !ok {
				log.Infof("network (%s) az (%s) not found", subnet.SubnetId, subnet.ZoneName)
				continue
			}
			vpcLcuuid, ok := vpcIdToLcuuid[subnet.VPCId]
			if !ok {
				log.Infof("network (%s) vpc (%s) not found", subnet.SubnetId, subnet.VPCId)
				continue
			}

			networkLcuuid := common.GenerateUUID(subnet.SubnetId)
			retNetwork := model.Network{
				Lcuuid:       networkLcuuid,
				Name:         subnet.Name,
				VPCLcuuid:    vpcLcuuid,
				Shared:       false,
				External:     false,
				NetType:      common.NETWORK_TYPE_LAN,
				AZLcuuid:     azLcuuid,
				RegionLcuuid: region.Lcuuid,
			}
			retNetworks = append(retNetworks, retNetwork)
			networkIdToLcuuid[subnet.SubnetId] = networkLcuuid
			b.azLcuuidToResourceNum[retNetwork.AZLcuuid]++
			b.regionLcuuidToResourceNum[retNetwork.RegionLcuuid]++

			retSubnet := model.Subnet{
				Lcuuid:        common.GenerateUUID(networkLcuuid),
				Name:          subnet.Name,
				CIDR:          subnet.Cidr,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
			}
			retSubnets = append(retSubnets, retSubnet)
		}
	}
	log.Debug("Get networks complete")
	return retNetworks, retSubnets, networkIdToLcuuid, nil
}
