package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type LB struct {
	OperatorBase[mysql.LB]
}

func NewLB() *LB {
	operater := &LB{
		OperatorBase[mysql.LB]{
			resourceTypeName: common.RESOURCE_TYPE_LB_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *LB) setDBItemID(dbItem *mysql.LB, id int) {
	dbItem.ID = id
}
