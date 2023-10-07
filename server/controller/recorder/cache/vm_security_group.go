/**
 * Copyright (c) 2023 Yunshan Networks
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

package cache

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (b *DiffBaseDataSet) addVMSecurityGroup(dbItem *mysql.VMSecurityGroup, seq int) {
	b.VMSecurityGroups[dbItem.Lcuuid] = &VMSecurityGroup{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Priority: dbItem.Priority,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN, b.VMSecurityGroups[dbItem.Lcuuid]))
}

func (b *DiffBaseDataSet) deleteVMSecurityGroup(lcuuid string) {
	delete(b.VMSecurityGroups, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN, lcuuid))
}

type VMSecurityGroup struct {
	DiffBase
	Priority int `json:"priority"`
}

func (s *VMSecurityGroup) Update(cloudItem *cloudmodel.VMSecurityGroup) {
	s.Priority = cloudItem.Priority
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_VM_SECURITY_GROUP_EN, s))
}
