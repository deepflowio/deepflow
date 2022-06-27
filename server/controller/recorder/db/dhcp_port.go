package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type DHCPPort struct {
	OperatorBase[mysql.DHCPPort]
}

func NewDHCPPort() *DHCPPort {
	operater := &DHCPPort{
		OperatorBase[mysql.DHCPPort]{
			resourceTypeName: common.RESOURCE_TYPE_DHCP_PORT_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *DHCPPort) setDBItemID(dbItem *mysql.DHCPPort, id int) {
	dbItem.ID = id
}
