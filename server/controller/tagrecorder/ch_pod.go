package tagrecorder

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

type ChPod struct {
	UpdaterBase[mysql.ChPod, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPod(resourceTypeToIconID map[IconKey]int) *ChPod {
	updater := &ChPod{
		UpdaterBase[mysql.ChPod, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPod) generateNewData() (map[IDKey]mysql.ChPod, bool) {
	var pods []mysql.Pod
	err := mysql.Db.Unscoped().Find(&pods).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPod)
	for _, pod := range pods {
		if pod.DeletedAt.Valid {
			keyToItem[IDKey{ID: pod.ID}] = mysql.ChPod{
				ID:     pod.ID,
				Name:   pod.Name + "(已删除)",
				IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD}],
			}
		} else {
			keyToItem[IDKey{ID: pod.ID}] = mysql.ChPod{
				ID:     pod.ID,
				Name:   pod.Name,
				IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD}],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPod) generateKey(dbItem mysql.ChPod) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPod) generateUpdateInfo(oldItem, newItem mysql.ChPod) (map[string]interface{}, bool) {
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
