package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type PodService struct {
	OperatorBase[mysql.PodService]
}

func NewPodService() *PodService {
	operater := &PodService{
		OperatorBase[mysql.PodService]{
			resourceTypeName: common.RESOURCE_TYPE_POD_SERVICE_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *PodService) setDBItemID(dbItem *mysql.PodService, id int) {
	dbItem.ID = id
}
