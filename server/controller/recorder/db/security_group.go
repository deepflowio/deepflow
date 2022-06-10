package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type SecurityGroup struct {
	OperatorBase[mysql.SecurityGroup]
}

func NewSecurityGroup() *SecurityGroup {
	operater := &SecurityGroup{
		OperatorBase[mysql.SecurityGroup]{
			resourceTypeName: common.RESOURCE_TYPE_SECURITY_GROUP_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *SecurityGroup) setDBItemID(dbItem *mysql.SecurityGroup, id int) {
	dbItem.ID = id
}
