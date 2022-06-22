package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type PodGroup struct {
	OperatorBase[mysql.PodGroup]
}

func NewPodGroup() *PodGroup {
	operater := &PodGroup{
		OperatorBase[mysql.PodGroup]{
			resourceTypeName: common.RESOURCE_TYPE_POD_GROUP_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *PodGroup) setDBItemID(dbItem *mysql.PodGroup, id int) {
	dbItem.ID = id
}
