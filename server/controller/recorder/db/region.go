package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type Region struct {
	OperatorBase[mysql.Region]
}

func NewRegion() *Region {
	operater := &Region{
		OperatorBase[mysql.Region]{
			resourceTypeName: common.RESOURCE_TYPE_REGION_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *Region) setDBItemID(dbItem *mysql.Region, id int) {
	dbItem.ID = id
}
