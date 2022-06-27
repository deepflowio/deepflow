package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type PodServicePort struct {
	OperatorBase[mysql.PodServicePort]
}

func NewPodServicePort() *PodServicePort {
	return &PodServicePort{
		OperatorBase[mysql.PodServicePort]{
			resourceTypeName: common.RESOURCE_TYPE_POD_SERVICE_PORT_EN,
			softDelete:       false,
		},
	}
}
