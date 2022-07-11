package kubernetes_gather

import (
	"github.com/metaflowys/metaflow/server/controller/cloud/model"
	"github.com/metaflowys/metaflow/server/controller/common"

	uuid "github.com/satori/go.uuid"
)

func GetVPCLcuuidFromUUIDGenerate(uuidGenerate string) string {
	return common.GetUUID(uuidGenerate+K8S_VPC_NAME, uuid.Nil)
}

func (k *KubernetesGather) getVPC() (model.VPC, error) {
	log.Debug("get vpc starting")
	if k.VPCUuid == "" {
		k.VPCUuid = GetVPCLcuuidFromUUIDGenerate(k.UuidGenerate)
	}
	vpc := model.VPC{
		Lcuuid:       k.VPCUuid,
		Name:         k.Name,
		RegionLcuuid: k.RegionUuid,
	}
	log.Debug("get vpc complete")
	return vpc, nil
}
