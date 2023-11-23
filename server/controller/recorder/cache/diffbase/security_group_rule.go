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

package diffbase

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
)

func (b *DataSet) AddSecurityGroupRule(dbItem *mysql.SecurityGroupRule, seq int) {
	b.SecurityGroupRules[dbItem.Lcuuid] = &SecurityGroupRule{
		DiffBase: DiffBase{
			Sequence: seq,
			Lcuuid:   dbItem.Lcuuid,
		},
		Priority:        dbItem.Priority,
		EtherType:       dbItem.EtherType,
		Local:           dbItem.Local,
		Remote:          dbItem.Remote,
		RemotePortRange: dbItem.RemotePortRange,
	}
	b.GetLogFunc()(addDiffBase(ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN, b.SecurityGroupRules[dbItem.Lcuuid]))
}

func (b *DataSet) DeleteSecurityGroupRule(lcuuid string) {
	delete(b.SecurityGroupRules, lcuuid)
	log.Info(deleteDiffBase(ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN, lcuuid))
}

type SecurityGroupRule struct {
	DiffBase
	Priority        int    `json:"priority"`
	EtherType       int    `json:"ether_type"`
	Local           string `json:"local"`
	Remote          string `json:"remote"`
	RemotePortRange string `json:"remote_port_range"`
}

func (s *SecurityGroupRule) Update(cloudItem *cloudmodel.SecurityGroupRule) {
	s.Priority = cloudItem.Priority
	s.EtherType = cloudItem.EtherType
	s.Local = cloudItem.Local
	s.Remote = cloudItem.Remote
	s.RemotePortRange = cloudItem.RemotePortRange
	log.Info(updateDiffBase(ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN, s))
}
