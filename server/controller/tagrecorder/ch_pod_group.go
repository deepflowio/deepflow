package tagrecorder

import (
	"server/controller/db/mysql"
)

type ChPodGroup struct {
	UpdaterBase[mysql.ChPodGroup, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodGroup(resourceTypeToIconID map[IconKey]int) *ChPodGroup {
	updater := &ChPodGroup{
		UpdaterBase[mysql.ChPodGroup, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_GROUP,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodGroup) generateNewData() (map[IDKey]mysql.ChPodGroup, bool) {
	var podGroups []mysql.PodGroup
	err := mysql.Db.Find(&podGroups).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPodGroup)
	for _, podGroup := range podGroups {
		keyToItem[IDKey{ID: podGroup.ID}] = mysql.ChPodGroup{
			ID:     podGroup.ID,
			Name:   podGroup.Name,
			IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_GROUP}],
		}
	}
	return keyToItem, true
}

func (p *ChPodGroup) generateKey(dbItem mysql.ChPodGroup) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodGroup) generateUpdateInfo(oldItem, newItem mysql.ChPodGroup) (map[string]interface{}, bool) {
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
