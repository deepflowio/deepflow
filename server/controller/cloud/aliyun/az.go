package aliyun

import (
	vpc "github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
)

func (a *Aliyun) getAZs(region model.Region) ([]model.AZ, error) {
	var retAZs []model.AZ

	log.Debug("get azs starting")
	request := vpc.CreateDescribeZonesRequest()
	response, err := a.getAZResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retAZs, err
	}

	for _, r := range response {
		azs, _ := r.Get("Zone").Array()
		for i := range azs {
			az := r.Get("Zone").GetIndex(i)

			zoneId := az.Get("ZoneId").MustString()
			retAZ := model.AZ{
				Lcuuid:       common.GenerateUUID(a.uuidGenerate + "_" + zoneId),
				Name:         az.Get("LocalName").MustString(),
				Label:        zoneId,
				RegionLcuuid: a.getRegionLcuuid(region.Lcuuid),
			}
			retAZs = append(retAZs, retAZ)
		}
	}
	log.Debug("get azs complete")
	return retAZs, nil
}
