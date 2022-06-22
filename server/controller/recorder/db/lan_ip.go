package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
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
