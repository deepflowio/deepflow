package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
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
