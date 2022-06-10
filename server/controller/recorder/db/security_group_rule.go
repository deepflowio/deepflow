package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type SecurityGroupRule struct {
	OperatorBase[mysql.SecurityGroupRule]
}

func NewSecurityGroupRule() *SecurityGroupRule {
	return &SecurityGroupRule{
		OperatorBase[mysql.SecurityGroupRule]{
			resourceTypeName: common.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN,
			softDelete:       false,
		},
	}
}
