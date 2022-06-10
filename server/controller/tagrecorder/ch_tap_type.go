package tagrecorder

import (
	"server/controller/db/mysql"
)

type ChTapType struct {
	UpdaterBase[mysql.ChTapType, TapTypeKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChTapType(resourceTypeToIconID map[IconKey]int) *ChTapType {
	updater := &ChTapType{
		UpdaterBase[mysql.ChTapType, TapTypeKey]{
			resourceTypeName: RESOURCE_TYPE_TAP_TYPE,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (t *ChTapType) generateNewData() (map[TapTypeKey]mysql.ChTapType, bool) {
	var tapTypes []mysql.TapType
	err := mysql.Db.Find(&tapTypes).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(t.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[TapTypeKey]mysql.ChTapType)
	for _, tapType := range tapTypes {
		keyToItem[TapTypeKey{Value: tapType.Value}] = mysql.ChTapType{
			Value: tapType.Value,
			Name:  tapType.Name,
		}
	}
	return keyToItem, true
}

func (t *ChTapType) generateKey(dbItem mysql.ChTapType) TapTypeKey {
	return TapTypeKey{Value: dbItem.Value}
}

func (t *ChTapType) generateUpdateInfo(oldItem, newItem mysql.ChTapType) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
