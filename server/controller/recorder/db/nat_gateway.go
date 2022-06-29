package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type NATGateway struct {
	OperatorBase[mysql.NATGateway]
}

func NewNATGateway() *NATGateway {
	operater := &NATGateway{
		OperatorBase[mysql.NATGateway]{
			resourceTypeName: common.RESOURCE_TYPE_NAT_GATEWAY_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *NATGateway) setDBItemID(dbItem *mysql.NATGateway, id int) {
	dbItem.ID = id
}
