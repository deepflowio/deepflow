package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type PodGroupPort struct {
	OperatorBase[mysql.PodGroupPort]
}

func NewPodGroupPort() *PodGroupPort {
	return &PodGroupPort{
		OperatorBase[mysql.PodGroupPort]{
			resourceTypeName: common.RESOURCE_TYPE_POD_GROUP_PORT_EN,
			softDelete:       false,
		},
	}
}
