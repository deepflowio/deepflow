package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type LANIP struct {
	OperatorBase[mysql.LANIP]
}

func NewLANIP() *LANIP {
	return &LANIP{
		OperatorBase[mysql.LANIP]{
			resourceTypeName: common.RESOURCE_TYPE_LAN_IP_EN,
			softDelete:       false,
		},
	}
}
