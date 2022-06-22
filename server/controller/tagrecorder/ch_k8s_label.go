package tagrecorder

import (
	"strings"

	"server/controller/db/mysql"
)

type ChK8sLabel struct {
	UpdaterBase[mysql.ChK8sLabel, K8sLabelKey]
}

func NewChK8sLabel() *ChK8sLabel {
	updater := &ChK8sLabel{
		UpdaterBase[mysql.ChK8sLabel, K8sLabelKey]{
			resourceTypeName: RESOURCE_TYPE_CH_K8S_LABEL,
		},
	}
	updater.dataGenerator = updater
	return updater
}

func (k *ChK8sLabel) generateNewData() (map[K8sLabelKey]mysql.ChK8sLabel, bool) {
	var pods []mysql.Pod
	var podGroups []mysql.PodGroup
	var podClusters []mysql.PodCluster
	err := mysql.Db.Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Find(&podGroups).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err))
		return nil, false
	}
	err = mysql.Db.Find(&podClusters).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(k.resourceTypeName, err))
		return nil, false
	}

	podClusterIDToVPCID := make(map[int]int)
	for _, podCluster := range podClusters {
		podClusterIDToVPCID[podCluster.ID] = podCluster.VPCID
	}
	keyToItem := make(map[K8sLabelKey]mysql.ChK8sLabel)
	for _, pod := range pods {
		splitLabel := strings.Split(pod.Label, ", ")
		for _, singleLabel := range splitLabel {
			splitSingleLabel := strings.Split(singleLabel, ":")
			if len(splitSingleLabel) == 2 {
				key := K8sLabelKey{
					PodID: pod.ID,
					Key:   splitSingleLabel[0],
				}
				keyToItem[key] = mysql.ChK8sLabel{
					PodID:   pod.ID,
					Key:     splitSingleLabel[0],
					Value:   splitSingleLabel[1],
					L3EPCID: pod.VPCID,
					PodNsID: pod.PodNamespaceID,
				}
			}
		}
	}
	return keyToItem, true
}

func (k *ChK8sLabel) generateKey(dbItem mysql.ChK8sLabel) K8sLabelKey {
	return K8sLabelKey{PodID: dbItem.PodID, Key: dbItem.Key}
}

func (k *ChK8sLabel) generateUpdateInfo(oldItem, newItem mysql.ChK8sLabel) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Value != newItem.Value {
		updateInfo["value"] = newItem.Value
	}
	if oldItem.L3EPCID != newItem.L3EPCID {
		updateInfo["l3_epc_id"] = newItem.L3EPCID
	}
	if oldItem.PodNsID != newItem.PodNsID {
		updateInfo["pod_ns_id"] = newItem.PodNsID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
