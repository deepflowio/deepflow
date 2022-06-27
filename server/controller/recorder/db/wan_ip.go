package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type WANIP struct {
	OperatorBase[mysql.WANIP]
}

func NewWANIP() *WANIP {
	return &WANIP{
		OperatorBase[mysql.WANIP]{
			resourceTypeName: common.RESOURCE_TYPE_WAN_IP_EN,
			softDelete:       false,
		},
	}
}
