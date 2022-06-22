package tagrecorder

import (
	"server/controller/db/mysql"
)

type ChPodNamespace struct {
	UpdaterBase[mysql.ChPodNamespace, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNamespace(resourceTypeToIconID map[IconKey]int) *ChPodNamespace {
	updater := &ChPodNamespace{
		UpdaterBase[mysql.ChPodNamespace, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_NAMESPACE,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodNamespace) generateNewData() (map[IDKey]mysql.ChPodNamespace, bool) {
	var podNamespaces []mysql.PodNamespace
	err := mysql.Db.Find(&podNamespaces).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPodNamespace)
	for _, podNamespace := range podNamespaces {
		keyToItem[IDKey{ID: podNamespace.ID}] = mysql.ChPodNamespace{
			ID:     podNamespace.ID,
			Name:   podNamespace.Name,
			IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NAMESPACE}],
		}
	}
	return keyToItem, true
}

func (p *ChPodNamespace) generateKey(dbItem mysql.ChPodNamespace) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodNamespace) generateUpdateInfo(oldItem, newItem mysql.ChPodNamespace) (map[string]interface{}, bool) {
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
