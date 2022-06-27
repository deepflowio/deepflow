package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
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
