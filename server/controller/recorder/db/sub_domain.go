package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type SubDomain struct {
	OperatorBase[mysql.SubDomain]
}

func NewSubDomain() *SubDomain {
	return &SubDomain{
		OperatorBase[mysql.SubDomain]{
			resourceTypeName: common.RESOURCE_TYPE_SUB_DOMAIN_EN,
			softDelete:       false,
		},
	}
}
