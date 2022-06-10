package aliyun

import (
	vpc "github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"server/controller/cloud/model"
	"server/controller/common"
)

func (a *Aliyun) getVPCs(region model.Region) ([]model.VPC, error) {
	var retVPCs []model.VPC

	log.Debug("get vpcs starting")
	request := vpc.CreateDescribeVpcsRequest()
	response, err := a.getVpcResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retVPCs, err
	}

	for _, r := range response {
		vpcs, _ := r.Get("Vpc").Array()
		for i := range vpcs {
			vpc := r.Get("Vpc").GetIndex(i)

			vpcId := vpc.Get("VpcId").MustString()
			vpcName := vpc.Get("VpcName").MustString()
			cidr := vpc.Get("CidrBlock").MustString()
			if vpcName == "" {
				if cidr != "" {
					vpcName = cidr
				} else {
					vpcName = vpcId
				}
			}

			retVPC := model.VPC{
				Lcuuid:       common.GenerateUUID(vpcId),
				Name:         vpcName,
				Label:        vpcId,
				CIDR:         cidr,
				RegionLcuuid: a.getRegionLcuuid(region.Lcuuid),
			}
			retVPCs = append(retVPCs, retVPC)
			a.regionLcuuidToResourceNum[retVPC.RegionLcuuid]++
		}
	}
	log.Debug("get vpcs complete")
	return retVPCs, nil
}
