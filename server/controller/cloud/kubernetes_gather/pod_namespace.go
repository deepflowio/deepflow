package kubernetes_gather

import (
	"server/controller/cloud/model"
	"server/controller/common"

	"github.com/bitly/go-simplejson"
	uuid "github.com/satori/go.uuid"
)

func (k *KubernetesGather) getPodNamespaces() ([]model.PodNamespace, error) {
	log.Debug("get pod namespaces starting")
	podNamespaces := []model.PodNamespace{}
	for _, n := range k.k8sInfo["*v1.Namespace"] {
		nData, err := simplejson.NewJson([]byte(n))
		if err != nil {
			log.Errorf("pod namespace initialization simplejson error: (%s)", err.Error())
			return podNamespaces, err
		}
		metaData, ok := nData.CheckGet("metadata")
		if !ok {
			log.Info("pod namespace metadata not found")
			continue
		}
		uID := metaData.Get("uid").MustString()
		if uID == "" {
			log.Info("pod namespace uid not found")
			continue
		}
		name := metaData.Get("name").MustString()
		if name == "" {
			log.Infof("pod namespace (%s) name not found", uID)
			continue
		}
		k.namespaceToLcuuid[name] = uID
		podNamespace := model.PodNamespace{
			Lcuuid:           uID,
			Name:             name,
			PodClusterLcuuid: common.GetUUID(k.UuidGenerate, uuid.Nil),
			RegionLcuuid:     k.RegionUuid,
			AZLcuuid:         k.azLcuuid,
		}
		podNamespaces = append(podNamespaces, podNamespace)

	}
	log.Debug("get pod namespaces complete")
	return podNamespaces, nil
}
