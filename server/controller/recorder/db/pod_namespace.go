package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type PodNamespace struct {
	OperatorBase[mysql.PodNamespace]
}

func NewPodNamespace() *PodNamespace {
	operater := &PodNamespace{
		OperatorBase[mysql.PodNamespace]{
			resourceTypeName: common.RESOURCE_TYPE_POD_NAMESPACE_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *PodNamespace) setDBItemID(dbItem *mysql.PodNamespace, id int) {
	dbItem.ID = id
}
