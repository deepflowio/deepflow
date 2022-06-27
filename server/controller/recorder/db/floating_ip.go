package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
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
