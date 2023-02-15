/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package db

import (
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/common"
)

type PodIngressRuleBackend struct {
	OperatorBase[mysql.PodIngressRuleBackend]
}

func NewPodIngressRuleBackend() *PodIngressRuleBackend {
	return &PodIngressRuleBackend{
		OperatorBase[mysql.PodIngressRuleBackend]{
			resourceTypeName: common.RESOURCE_TYPE_POD_INGRESS_RULE_BACKEND_EN,
			softDelete:       false,
			allocateID:       false,
		},
	}
}
