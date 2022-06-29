package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type LBVMConnection struct {
	OperatorBase[mysql.LBVMConnection]
}

func NewLBVMConnection() *LBVMConnection {
	return &LBVMConnection{
		OperatorBase[mysql.LBVMConnection]{
			resourceTypeName: common.RESOURCE_TYPE_LB_VM_CONNECTION_EN,
			softDelete:       false,
		},
	}
}
