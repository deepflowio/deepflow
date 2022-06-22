package tagrecorder

import (
	"server/controller/db/mysql"
)

type ChPodCluster struct {
	UpdaterBase[mysql.ChPodCluster, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodCluster(resourceTypeToIconID map[IconKey]int) *ChPodCluster {
	updater := &ChPodCluster{
		UpdaterBase[mysql.ChPodCluster, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodCluster) generateNewData() (map[IDKey]mysql.ChPodCluster, bool) {
	var podClusters []mysql.PodCluster
	err := mysql.Db.Find(&podClusters).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPodCluster)
	for _, podCluster := range podClusters {
		keyToItem[IDKey{ID: podCluster.ID}] = mysql.ChPodCluster{
			ID:     podCluster.ID,
			Name:   podCluster.Name,
			IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_CLUSTER}],
		}
	}
	return keyToItem, true
}

func (p *ChPodCluster) generateKey(dbItem mysql.ChPodCluster) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodCluster) generateUpdateInfo(oldItem, newItem mysql.ChPodCluster) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID {
		updateInfo["icon_id"] = newItem.IconID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
