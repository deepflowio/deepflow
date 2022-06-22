package kubernetes_gather

import (
	"server/controller/cloud/model"
	"server/controller/common"
)

func (k *KubernetesGather) getRegion() (model.Region, error) {
	log.Debug("get region starting")
	var region model.Region
	if k.RegionUuid == "" {
		k.RegionUuid = common.DEFAULT_REGION
		region = model.Region{
			Lcuuid: common.DEFAULT_REGION,
			Name:   common.DEFAULT_REGION_NAME,
		}
	}
	log.Debug("get region complete")
	return region, nil
}
