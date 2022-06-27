package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
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
