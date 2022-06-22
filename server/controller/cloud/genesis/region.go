package genesis

import (
	"server/controller/cloud/model"
	"server/controller/common"
)

func (g *Genesis) getRegion() ([]model.Region, error) {
	log.Debug("get region starting")
	var regions []model.Region
	if g.regionUuid == "" {
		g.regionUuid = common.DEFAULT_REGION
		region := model.Region{
			Lcuuid: common.DEFAULT_REGION,
			Name:   g.defaultRegionName,
		}
		regions = append(regions, region)
	}
	log.Debug("get region complete")
	return regions, nil
}
