package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
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
