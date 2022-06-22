package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type AZ struct {
	OperatorBase[mysql.AZ]
}

func NewAZ() *AZ {
	operater := &AZ{
		OperatorBase[mysql.AZ]{
			resourceTypeName: common.RESOURCE_TYPE_AZ_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *AZ) setDBItemID(dbItem *mysql.AZ, id int) {
	dbItem.ID = id
}
