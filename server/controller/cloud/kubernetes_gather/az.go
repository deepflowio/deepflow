package kubernetes_gather

import (
	cloudcommon "github.com/metaflowys/metaflow/server/controller/cloud/common"
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
)

func (k *KubernetesGather) getAZ() (model.AZ, error) {
	log.Debug("get az starting")
	k.azLcuuid = cloudcommon.GetAZLcuuidFromUUIDGenerate(k.UuidGenerate)
	az := model.AZ{
		Lcuuid:       k.azLcuuid,
		Name:         k.Name,
		RegionLcuuid: k.RegionUuid,
	}
	log.Debug("get az complete")
	return az, nil
}
