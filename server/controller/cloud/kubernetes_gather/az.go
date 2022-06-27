package kubernetes_gather

import (
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"

	uuid "github.com/satori/go.uuid"
)

func (k *KubernetesGather) getAZ() (model.AZ, error) {
	log.Debug("get az starting")
	azLcuuid := common.GetUUID(k.UuidGenerate, uuid.Nil)
	// 根据region生成唯一az
	k.azLcuuid = azLcuuid[:len(azLcuuid)-2] + "ff"
	az := model.AZ{
		Lcuuid:       k.azLcuuid,
		Name:         k.Name,
		RegionLcuuid: k.RegionUuid,
	}
	log.Debug("get az complete")
	return az, nil
}
