package tagrecorder

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

type ChPodNode struct {
	UpdaterBase[mysql.ChPodNode, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChPodNode(resourceTypeToIconID map[IconKey]int) *ChPodNode {
	updater := &ChPodNode{
		UpdaterBase[mysql.ChPodNode, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_POD_NODE,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (p *ChPodNode) generateNewData() (map[IDKey]mysql.ChPodNode, bool) {
	var podNodes []mysql.PodNode
	err := mysql.Db.Unscoped().Find(&podNodes).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(p.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChPodNode)
	for _, podNode := range podNodes {
		if podNode.DeletedAt.Valid {
			keyToItem[IDKey{ID: podNode.ID}] = mysql.ChPodNode{
				ID:     podNode.ID,
				Name:   podNode.Name + "(已删除)",
				IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NODE}],
			}
		} else {
			keyToItem[IDKey{ID: podNode.ID}] = mysql.ChPodNode{
				ID:     podNode.ID,
				Name:   podNode.Name,
				IconID: p.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_POD_NODE}],
			}
		}
	}
	return keyToItem, true
}

func (p *ChPodNode) generateKey(dbItem mysql.ChPodNode) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (p *ChPodNode) generateUpdateInfo(oldItem, newItem mysql.ChPodNode) (map[string]interface{}, bool) {
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
