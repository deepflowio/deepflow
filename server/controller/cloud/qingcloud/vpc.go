package qingcloud

import (
	"github.com/deckarep/golang-set"

	"server/controller/cloud/model"
	"server/controller/common"
)

func (q *QingCloud) GetVPCs() ([]model.VPC, error) {
	var retVPCs []model.VPC
	var vpcIdToCidr map[string]string
	var regionIdToDefaultVPCLcuuid map[string]string

	log.Debug("get vpcs starting")

	vpcIds := mapset.NewSet()
	regionLcuuidToDefaultVPCLcuuid := make(map[string]string)
	vpcIdToCidr = make(map[string]string)
	regionIdToDefaultVPCLcuuid = make(map[string]string)
	for regionId, regionLcuuid := range q.RegionIdToLcuuid {
		kwargs := []*Param{
			{"zone", regionId},
			{"status.1", "active"},
			{"status.2", "poweroffed"},
		}
		response, err := q.GetResponse("DescribeRouters", "router_set", kwargs)
		if err != nil {
			log.Error(err)
			return nil, err
		}

		for _, r := range response {
			for i := range r.MustArray() {
				vpc := r.GetIndex(i)
				err := q.CheckRequiredAttributes(vpc, []string{"router_id"})
				if err != nil {
					continue
				}

				// 不同可用区会返回相同的vpc，需要做去重处理
				vpcId := vpc.Get("router_id").MustString()
				if vpcIds.Contains(vpcId) {
					continue
				}
				vpcIds.Add(vpcId)

				vpcLcuuid := common.GenerateUUID(vpcId)
				vpcName := vpc.Get("router_name").MustString()
				if vpcName == "" {
					vpcName = vpcId
				}
				vpcNetwork := vpc.Get("vpc_network").MustString()
				if vpcNetwork != "" {
					vpcIdToCidr[vpcId] = vpcNetwork
				}
				retVPCs = append(retVPCs, model.VPC{
					Lcuuid:       vpcLcuuid,
					Name:         vpcName,
					Label:        vpcId,
					CIDR:         vpcNetwork,
					RegionLcuuid: regionLcuuid,
				})
				q.regionLcuuidToResourceNum[regionLcuuid]++
			}
		}

		defaultVPCLcuuid := common.GenerateUUID(
			q.UuidGenerate + "_default_vpc_" + regionLcuuid,
		)
		regionIdToDefaultVPCLcuuid[regionId] = defaultVPCLcuuid

		// 每个区域定义一个default VPC
		if _, ok := regionLcuuidToDefaultVPCLcuuid[regionLcuuid]; ok {
			continue
		}
		regionLcuuidToDefaultVPCLcuuid[regionLcuuid] = defaultVPCLcuuid
		retVPCs = append(retVPCs, model.VPC{
			Lcuuid:       defaultVPCLcuuid,
			Name:         q.defaultVPCName,
			RegionLcuuid: regionLcuuid,
		})
	}

	q.vpcIdToCidr = vpcIdToCidr
	q.regionIdToDefaultVPCLcuuid = regionIdToDefaultVPCLcuuid

	log.Debug("get vpcs complete")
	return retVPCs, nil
}
