package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type LBTargetServer struct {
	OperatorBase[mysql.LBTargetServer]
}

func NewLBTargetServer() *LBTargetServer {
	return &LBTargetServer{
		OperatorBase[mysql.LBTargetServer]{
			resourceTypeName: common.RESOURCE_TYPE_LB_TARGET_SERVER_EN,
			softDelete:       false,
		},
	}
}
