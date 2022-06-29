package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type Network struct {
	OperatorBase[mysql.Network]
}

func NewNetwork() *Network {
	operater := &Network{
		OperatorBase[mysql.Network]{
			resourceTypeName: common.RESOURCE_TYPE_NETWORK_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *Network) setDBItemID(dbItem *mysql.Network, id int) {
	dbItem.ID = id
}
