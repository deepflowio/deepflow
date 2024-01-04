/*
 * Copyright (c) 2024 Yunshan Networks
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
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

type Subnet struct {
	OperatorBase[mysql.Subnet]
}

func NewSubnet() *Subnet {
	o := &Subnet{
		OperatorBase[mysql.Subnet]{
			resourceTypeName: ctrlrcommon.RESOURCE_TYPE_SUBNET_EN,
			softDelete:       false,
			allocateID:       false,
		},
	}
	o.setFieldsNeededAfterCreate([]string{"id", "lcuuid", "name", "label", "sub_domain"})
	return o
}
