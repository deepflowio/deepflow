package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type VMSecurityGroup struct {
	OperatorBase[mysql.VMSecurityGroup]
}

func NewVMSecurityGroup() *VMSecurityGroup {
	return &VMSecurityGroup{
		OperatorBase[mysql.VMSecurityGroup]{
			resourceTypeName: common.RESOURCE_TYPE_VM_SECURITY_GROUP_EN,
			softDelete:       false,
		},
	}
}
