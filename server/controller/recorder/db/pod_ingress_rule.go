package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type PodIngressRule struct {
	OperatorBase[mysql.PodIngressRule]
}

func NewPodIngressRule() *PodIngressRule {
	return &PodIngressRule{
		OperatorBase[mysql.PodIngressRule]{
			resourceTypeName: common.RESOURCE_TYPE_POD_INGRESS_RULE_EN,
			softDelete:       false,
		},
	}
}
