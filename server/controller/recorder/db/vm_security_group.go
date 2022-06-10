package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
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
