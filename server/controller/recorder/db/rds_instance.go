package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type RDSInstance struct {
	OperatorBase[mysql.RDSInstance]
}

func NewRDSInstance() *RDSInstance {
	operater := &RDSInstance{
		OperatorBase[mysql.RDSInstance]{
			resourceTypeName: common.RESOURCE_TYPE_RDS_INSTANCE_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *RDSInstance) setDBItemID(dbItem *mysql.RDSInstance, id int) {
	dbItem.ID = id
}
