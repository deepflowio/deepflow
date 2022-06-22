package aliyun

import (
	ecs "github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"server/controller/cloud/model"
	"server/controller/common"
	"sort"
)

func (a *Aliyun) getRegions() ([]model.Region, error) {
	var retRegions []model.Region

	log.Debug("get regions starting")
	request := ecs.CreateDescribeRegionsRequest()
	response, err := a.getRegionResponse(a.regionName, request)
	if err != nil {
		log.Error(err)
		return retRegions, err
	}

	for _, r := range response {
		regions, _ := r.Get("Region").Array()
		for i := range regions {
			region := r.Get("Region").GetIndex(i)

			localName := region.Get("LocalName").MustString()
			// 当存在区域白名单时，如果当前区域不在白名单中，则跳过
			if len(a.includeRegions) > 0 {
				regionIndex := sort.SearchStrings(a.includeRegions, localName)
				if regionIndex == len(a.includeRegions) || a.includeRegions[regionIndex] != localName {
					log.Infof("region (%s) not in include_regions", localName)
					continue
				}
			}
			// 当存在区域黑名单是，如果当前区域在黑名单中，则跳过
			if len(a.excludeRegions) > 0 {
				regionIndex := sort.SearchStrings(a.excludeRegions, localName)
				if regionIndex < len(a.excludeRegions) && a.excludeRegions[regionIndex] == localName {
					log.Infof("region (%s) in exclude_regions", localName)
					continue
				}
			}

			retRegion := model.Region{
				Lcuuid: common.GenerateUUID(region.Get("RegionId").MustString()),
				Label:  region.Get("RegionId").MustString(),
				Name:   localName,
			}
			retRegions = append(retRegions, retRegion)
		}
	}

	log.Debug("get regions complete")
	return retRegions, nil
}
