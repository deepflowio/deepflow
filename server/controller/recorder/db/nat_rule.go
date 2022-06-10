package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type NATRule struct {
	OperatorBase[mysql.NATRule]
}

func NewNATRule() *NATRule {
	return &NATRule{
		OperatorBase[mysql.NATRule]{
			resourceTypeName: common.RESOURCE_TYPE_NAT_RULE_EN,
			softDelete:       false,
		},
	}
}
