package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type CEN struct {
	OperatorBase[mysql.CEN]
}

func NewCEN() *CEN {
	operater := &CEN{
		OperatorBase[mysql.CEN]{
			resourceTypeName: common.RESOURCE_TYPE_CEN_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *CEN) setDBItemID(dbItem *mysql.CEN, id int) {
	dbItem.ID = id
}
