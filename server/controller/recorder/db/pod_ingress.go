package db

import (
	"server/controller/db/mysql"
	"server/controller/recorder/common"
)

type PodIngress struct {
	OperatorBase[mysql.PodIngress]
}

func NewPodIngress() *PodIngress {
	operater := &PodIngress{
		OperatorBase[mysql.PodIngress]{
			resourceTypeName: common.RESOURCE_TYPE_POD_INGRESS_EN,
			softDelete:       true,
		},
	}
	operater.setter = operater
	return operater
}

func (a *PodIngress) setDBItemID(dbItem *mysql.PodIngress, id int) {
	dbItem.ID = id
}
