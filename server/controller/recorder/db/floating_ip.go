package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type FloatingIP struct {
	OperatorBase[mysql.FloatingIP]
}

func NewFloatingIP() *FloatingIP {
	return &FloatingIP{
		OperatorBase[mysql.FloatingIP]{
			resourceTypeName: common.RESOURCE_TYPE_FLOATING_IP_EN,
			softDelete:       false,
		},
	}
}
