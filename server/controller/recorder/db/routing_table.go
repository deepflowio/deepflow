package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
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
