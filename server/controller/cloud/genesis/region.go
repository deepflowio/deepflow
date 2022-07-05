package genesis

import (
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"
)

func (g *Genesis) getRegion() ([]model.Region, error) {
	log.Debug("get region starting")
	var regions []model.Region

	g.cloudStatsd.APICost["region"] = []int{0}
	g.cloudStatsd.APICount["region"] = []int{0}

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
