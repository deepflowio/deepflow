package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type NATVMConnection struct {
	OperatorBase[mysql.NATVMConnection]
}

func NewNATVMConnection() *NATVMConnection {
	return &NATVMConnection{
		OperatorBase[mysql.NATVMConnection]{
			resourceTypeName: common.RESOURCE_TYPE_NAT_VM_CONNECTION_EN,
			softDelete:       false,
		},
	}
}
