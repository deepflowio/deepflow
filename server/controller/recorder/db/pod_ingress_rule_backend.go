package db

import (
	"github.com/metaflowys/metaflow/server/controller/db/mysql"
	"github.com/metaflowys/metaflow/server/controller/recorder/common"
)

type PodIngressRuleBackend struct {
	OperatorBase[mysql.PodIngressRuleBackend]
}

func NewPodIngressRuleBackend() *PodIngressRuleBackend {
	return &PodIngressRuleBackend{
		OperatorBase[mysql.PodIngressRuleBackend]{
			resourceTypeName: common.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN,
			softDelete:       false,
		},
	}
}
