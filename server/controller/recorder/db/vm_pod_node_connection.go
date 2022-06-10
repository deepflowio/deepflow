package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type VMPodNodeConnection struct {
	OperatorBase[mysql.VMPodNodeConnection]
}

func NewVMPodNodeConnection() *VMPodNodeConnection {
	return &VMPodNodeConnection{
		OperatorBase[mysql.VMPodNodeConnection]{
			resourceTypeName: common.RESOURCE_TYPE_VM_POD_NODE_CONNECTION_EN,
			softDelete:       false,
		},
	}
}
