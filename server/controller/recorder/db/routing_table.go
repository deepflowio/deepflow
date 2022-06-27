package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type RoutingTable struct {
	OperatorBase[mysql.RoutingTable]
}

func NewRoutingTable() *RoutingTable {
	return &RoutingTable{
		OperatorBase[mysql.RoutingTable]{
			resourceTypeName: common.RESOURCE_TYPE_ROUTING_TABLE_EN,
			softDelete:       false,
		},
	}
}
