package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
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
