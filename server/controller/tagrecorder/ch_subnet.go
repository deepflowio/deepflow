package tagrecorder

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

type ChNetwork struct {
	UpdaterBase[mysql.ChNetwork, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChNetwork(resourceTypeToIconID map[IconKey]int) *ChNetwork {
	updater := &ChNetwork{
		UpdaterBase[mysql.ChNetwork, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_NETWORK,
		},
		resourceTypeToIconID,
	}

	updater.dataGenerator = updater
	return updater
}

func (n *ChNetwork) generateNewData() (map[IDKey]mysql.ChNetwork, bool) {
	var networks []mysql.Network
	err := mysql.Db.Find(&networks).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(n.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChNetwork)
	for _, network := range networks {
		keyToItem[IDKey{ID: network.ID}] = mysql.ChNetwork{
			ID:     network.ID,
			Name:   network.Name,
			IconID: n.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VL2}],
		}
	}
	return keyToItem, true
}

func (n *ChNetwork) generateKey(dbItem mysql.ChNetwork) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (n *ChNetwork) generateUpdateInfo(oldItem, newItem mysql.ChNetwork) (map[string]interface{}, bool) {
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
