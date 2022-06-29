package tagrecorder

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
)

type ChVPC struct {
	UpdaterBase[mysql.ChVPC, IDKey]
	resourceTypeToIconID map[IconKey]int
}

func NewChVPC(resourceTypeToIconID map[IconKey]int) *ChVPC {
	updater := &ChVPC{
		UpdaterBase[mysql.ChVPC, IDKey]{
			resourceTypeName: RESOURCE_TYPE_CH_VPC,
		},
		resourceTypeToIconID,
	}
	updater.dataGenerator = updater
	return updater
}

func (v *ChVPC) generateNewData() (map[IDKey]mysql.ChVPC, bool) {
	var vpcs []mysql.VPC
	err := mysql.Db.Unscoped().Find(&vpcs).Error
	if err != nil {
		log.Errorf(dbQueryResourceFailed(v.resourceTypeName, err))
		return nil, false
	}

	keyToItem := make(map[IDKey]mysql.ChVPC)
	for _, vpc := range vpcs {
		if vpc.DeletedAt.Valid {
			keyToItem[IDKey{ID: vpc.ID}] = mysql.ChVPC{
				ID:     vpc.ID,
				Name:   vpc.Name + "(已删除)",
				UID:    vpc.UID,
				IconID: v.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VPC}],
			}
		} else {
			keyToItem[IDKey{ID: vpc.ID}] = mysql.ChVPC{
				ID:     vpc.ID,
				Name:   vpc.Name,
				UID:    vpc.UID,
				IconID: v.resourceTypeToIconID[IconKey{NodeType: RESOURCE_TYPE_VPC}],
			}
		}
	}
	return keyToItem, true
}

func (v *ChVPC) generateKey(dbItem mysql.ChVPC) IDKey {
	return IDKey{ID: dbItem.ID}
}

func (v *ChVPC) generateUpdateInfo(oldItem, newItem mysql.ChVPC) (map[string]interface{}, bool) {
	updateInfo := make(map[string]interface{})
	if oldItem.Name != newItem.Name {
		updateInfo["name"] = newItem.Name
	}
	if oldItem.IconID != newItem.IconID {
		updateInfo["icon_id"] = newItem.IconID
	}
	if oldItem.UID != newItem.UID {
		updateInfo["uid"] = newItem.UID
	}
	if len(updateInfo) > 0 {
		return updateInfo, true
	}
	return nil, false
}
