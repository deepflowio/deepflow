package baidubce

import (
	"github.com/baidubce/bce-sdk-go/services/vpc"

	"server/controller/cloud/model"
	"server/controller/common"
)

func (b *BaiduBce) getVPCs(region model.Region) ([]model.VPC, map[string]string, map[string]string, error) {
	var retVPCs []model.VPC
	var vpcIdToLcuuid map[string]string
	var vpcIdToName map[string]string

	log.Debug("get vpcs starting")

	vpcClient, _ := vpc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	marker := ""
	args := &vpc.ListVPCArgs{}
	results := make([]*vpc.ListVPCResult, 0)
	for {
		args.Marker = marker
		result, err := vpcClient.ListVPC(args)
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

	vpcIdToName = make(map[string]string)
	vpcIdToLcuuid = make(map[string]string)
	for _, r := range results {
		for _, vpc := range r.VPCs {
			vpcLcuuid := common.GenerateUUID(vpc.VPCID)
			retVPC := model.VPC{
				Lcuuid:       vpcLcuuid,
				Name:         vpc.Name,
				CIDR:         vpc.Cidr,
				RegionLcuuid: region.Lcuuid,
			}
			retVPCs = append(retVPCs, retVPC)
			vpcIdToName[vpc.VPCID] = vpc.Name
			vpcIdToLcuuid[vpc.VPCID] = vpcLcuuid
			b.regionLcuuidToResourceNum[retVPC.RegionLcuuid]++
		}
	}
	log.Debug("Get vpcs complete")
	return retVPCs, vpcIdToLcuuid, vpcIdToName, nil
}
