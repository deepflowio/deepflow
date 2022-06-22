package tagrecorder

import (
	"server/controller/db/mysql"
)

type ChAZ struct {
	UpdaterBase[mysql.ChAZ, IDKey]
	domainLcuuidToIconID map[string]int
	resourceTypeToIconID map[IconKey]int
}

func NewChAZ(domainLcuuidToIconID map[string]int, resourceTypeToIconID map[IconKey]int) *ChAZ {
	updater := &ChAZ{
		UpdaterBase[mysql.ChAZ, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_AZ,
		},
		domainLcuuidToIconID,
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (a *ChAZ) generateNewData() (map[IDKey]mysql.ChAZ, bool) {
	log.Infof("generate data for %s", a.resourceTypeName)
	var azs []mysql.AZ

	err := mysql.Db.Find(&azs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(a.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChAZ)
	for _, az := range azs {
		iconID := a.domainLcuuidToIconID[az.Domain]
		if iconID == 0 {
			key := IconKey{
				NodeType: RESOURCE_TYPE_AZ,
			}
			iconID = a.resourceTypeToIconID[key]
			if iconID == 0 {
				return keyToItem, false
			}
		}

		keyToItem[IDKey{ID: az.ID}] = mysql.ChAZ{
			ID:     az.ID,
			Name:   az.Name,
			IconID: iconID,
		}
	}
	return keyToItem, true
}

func (a *ChAZ) generateKey(dbItem mysql.ChAZ) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (a *ChAZ) generateUpdateInfo(oldItem, newItem mysql.ChAZ) (map[string]interface{}, bool) {
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
