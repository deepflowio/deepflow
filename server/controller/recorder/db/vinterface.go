package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type VInterface struct {
	OperatorBase[mysql.VInterface]
}

func NewVInterface() *VInterface {
	return &VInterface{
		OperatorBase[mysql.VInterface]{
			resourceTypeName: common.RESOURCE_TYPE_VINTERFACE_EN,
			softDelete:       false,
		},
	}
}
