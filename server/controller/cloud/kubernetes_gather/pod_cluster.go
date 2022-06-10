package kubernetes_gather

import (
	"server/controller/cloud/model"
	"server/controller/common"

	"github.com/bitly/go-simplejson"
	uuid "github.com/satori/go.uuid"
)

func (k *KubernetesGather) getPodCluster() (model.PodCluster, error) {
	log.Debug("get pod cluster starting")
	vInfo := k.k8sInfo["*version.Info"][0]
	vJson, vErr := simplejson.NewJson([]byte(vInfo))
	if vErr != nil {
		log.Errorf("pod cluster initialization version json error: (%s)", vErr.Error())
		return model.PodCluster{}, vErr
	}
	podCluster := model.PodCluster{
		Lcuuid:          common.GetUUID(k.UuidGenerate, uuid.Nil),
		Version:         K8S_VERSION_PREFIX + " " + vJson.Get("gitVersion").MustString(),
		Name:            k.Name,
		VPCLcuuid:       k.VPCUuid,
		AZLcuuid:        k.azLcuuid,
		RegionLcuuid:    k.RegionUuid,
		SubDomainLcuuid: common.GetUUID(k.UuidGenerate, uuid.Nil),
	}
	log.Debug("get pod cluster complete")
	return podCluster, nil
}
