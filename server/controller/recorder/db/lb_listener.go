package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type LBListener struct {
	OperatorBase[mysql.LBListener]
}

func NewLBListener() *LBListener {
	operater := &LBListener{
		OperatorBase[mysql.LBListener]{
			resourceTypeName: common.RESOURCE_TYPE_LB_LISTENER_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *LBListener) setDBItemID(dbItem *mysql.LBListener, id int) {
	dbItem.ID = id
}
