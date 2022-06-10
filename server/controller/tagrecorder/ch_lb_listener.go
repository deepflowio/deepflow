package tagrecorder

import (
	"server/controller/db/mysql"
)

type ChLbListener struct {
	UpdaterBase[mysql.ChLBListener, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChLbListener(resourceTypeToIconID map[IconKey]int) *ChLbListener {
	updater := &ChLbListener{
		UpdaterBase[mysql.ChLBListener, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_LB_LISTENER,
		},
		resourceTypeToIconID,
	}

	updater.dataGenerator = updater
	return updater
}

func (l *ChLbListener) generateNewData() (map[IDKey]mysql.ChLBListener, bool) {
	var lbListeners []mysql.LBListener
	err := mysql.Db.Find(&lbListeners).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(l.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChLBListener)
	for _, lbListener := range lbListeners {
		keyToItem[IDKey{ID: lbListener.ID}] = mysql.ChLBListener{
			ID:   lbListener.ID,
			Name: lbListener.Name,
		}
	}
	return keyToItem, true
}

func (l *ChLbListener) generateKey(dbItem mysql.ChLBListener) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (l *ChLbListener) generateUpdateInfo(oldItem, newItem mysql.ChLBListener) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
