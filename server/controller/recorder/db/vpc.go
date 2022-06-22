package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type VPC struct {
	OperatorBase[mysql.VPC]
}

func NewVPC() *VPC {
	operater := &VPC{
		OperatorBase[mysql.VPC]{
			resourceTypeName: common.RESOURCE_TYPE_VPC_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *VPC) setDBItemID(dbItem *mysql.VPC, id int) {
	dbItem.ID = id
}
