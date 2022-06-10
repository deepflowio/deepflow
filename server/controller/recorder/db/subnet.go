package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type Subnet struct {
	OperatorBase[mysql.Subnet]
}

func NewSubnet() *Subnet {
	return &Subnet{
		OperatorBase[mysql.Subnet]{
			resourceTypeName: common.RESOURCE_TYPE_SUBNET_EN,
			softDelete:       false,
		},
	}
}
