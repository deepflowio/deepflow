package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type PodCluster struct {
	OperatorBase[mysql.PodCluster]
}

func NewPodCluster() *PodCluster {
	operater := &PodCluster{
		OperatorBase[mysql.PodCluster]{
			resourceTypeName: common.RESOURCE_TYPE_POD_CLUSTER_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *PodCluster) setDBItemID(dbItem *mysql.PodCluster, id int) {
	dbItem.ID = id
}
