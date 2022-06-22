package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
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
