package aliyun

import (
	vpc "github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"server/controller/cloud/model"
	"server/controller/common"
)

func (a *Aliyun) getNetworks(region model.Region) ([]model.Network, []model.Subnet, error) {
	var retNetworks []model.Network
	var retSubnets []model.Subnet

	log.Debug("get networks starting")
	request := vpc.CreateDescribeVSwitchesRequest()
	response, err := a.getNetworkResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retNetworks, retSubnets, err
	}
	for _, r := range response {
		networks, _ := r.Get("VSwitch").Array()
		for i := range networks {
			network := r.Get("VSwitch").GetIndex(i)

			err := a.checkRequiredAttributes(
				network,
				[]string{"VSwitchId", "VSwitchName", "VpcId", "ZoneId", "CidrBlock"},
			)
			if err != nil {
				continue
			}
			networkId := network.Get("VSwitchId").MustString()
			networkName := network.Get("VSwitchName").MustString()
			if networkName == "" {
				networkName = networkId
			}
			vpcId := network.Get("VpcId").MustString()
			azId := network.Get("ZoneId").MustString()
			cidr := network.Get("CidrBlock").MustString()

			networkLcuuid := common.GenerateUUID(networkId)
			vpcLcuuid := common.GenerateUUID(vpcId)
			retNetwork := model.Network{
				Lcuuid:         networkLcuuid,
				Name:           networkName,
				SegmentationID: 1,
				VPCLcuuid:      vpcLcuuid,
				Shared:         false,
				External:       false,
				NetType:        common.NETWORK_TYPE_LAN,
				AZLcuuid:       common.GenerateUUID(a.uuidGenerate + "_" + azId),
				RegionLcuuid:   a.getRegionLcuuid(region.Lcuuid),
			}
			retNetworks = append(retNetworks, retNetwork)
			a.azLcuuidToResourceNum[retNetwork.AZLcuuid]++
			a.regionLcuuidToResourceNum[retNetwork.RegionLcuuid]++

			retSubnet := model.Subnet{
				Lcuuid:        common.GenerateUUID(networkLcuuid),
				Name:          networkName,
				CIDR:          cidr,
				NetworkLcuuid: networkLcuuid,
				VPCLcuuid:     vpcLcuuid,
			}
			retSubnets = append(retSubnets, retSubnet)
		}
	}
	log.Debug("get networks complete")
	return retNetworks, retSubnets, nil
}
