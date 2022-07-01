package tagrecorder

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

type ChVTap struct {
	UpdaterBase[mysql.ChVTap, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChVTap(resourceTypeToIconID map[IconKey]int) *ChVTap {
	updater := &ChVTap{
		UpdaterBase[mysql.ChVTap, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_VTAP,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (v *ChVTap) generateNewData() (map[IDKey]mysql.ChVTap, bool) {
	var vTaps []mysql.VTap
	err := mysql.Db.Find(&vTaps).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChVTap)
	for _, vTap := range vTaps {
		keyToItem[IDKey{ID: vTap.ID}] = mysql.ChVTap{
			ID:   vTap.ID,
			Name: vTap.Name,
			Type: vTap.Type,
		}
	}
	return keyToItem, true
}

func (v *ChVTap) generateKey(dbItem mysql.ChVTap) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (v *ChVTap) generateUpdateInfo(oldItem, newItem mysql.ChVTap) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.Type != newItem.Type {
		updateInfo["type"] = newItem.Type
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
