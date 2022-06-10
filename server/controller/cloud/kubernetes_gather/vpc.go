package kubernetes_gather

import (
	"server/controller/cloud/model"
	"server/controller/common"

	uuid "github.com/satori/go.uuid"
)

func (k *KubernetesGather) getVPC() (model.VPC, error) {
	log.Debug("get vpc starting")
	if k.VPCUuid == "" {
		k.VPCUuid = common.GetUUID(k.UuidGenerate+K8S_VPC_NAME, uuid.Nil)
	}
	vpc := model.VPC{
		Lcuuid:       k.VPCUuid,
		Name:         k.Name,
		RegionLcuuid: k.RegionUuid,
	}
	log.Debug("get vpc complete")
	return vpc, nil
}
