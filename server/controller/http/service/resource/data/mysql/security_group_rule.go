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

package mysql

import (
	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type SecurityGroupRule struct {
	DataProvider
	toolData *securityGroupRuleToolData
}

func NewSecurityGroupRule() *SecurityGroupRule {
	dp := &SecurityGroupRule{newDataProvider(ctrlrcommon.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN), new(securityGroupRuleToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *SecurityGroupRule) generate() ([]common.ResponseElem, error) {
	data := make([]common.ResponseElem, 0)
	err := p.toolData.Init().Load()
	if err != nil {
		return data, err
	}
	for _, item := range p.toolData.sgRules {
		data = append(data, p.generateOne(item))
	}
	return data, nil
}

func (a *SecurityGroupRule) generateOne(item mysql.SecurityGroupRule) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["SECURITY_GROUP_NAME"] = a.toolData.sgIDToName[item.SecurityGroupID]
	var local, localPortRange, remote, remotePortRange string
	if item.Direction == ctrlrcommon.SECURITY_GROUP_RULE_INGRESS {
		if lc, ok := a.toolData.sgLcuuidToName[item.Remote]; ok {
			local = lc
		} else {
			local = item.Remote
		}
		localPortRange = item.RemotePortRange
		remote = a.toolData.sgLcuuidToName[item.Local]
		if rm, ok := a.toolData.sgLcuuidToName[item.Local]; ok {
			remote = rm
		} else {
			remote = item.Local
		}
		remotePortRange = item.LocalPortRange
	} else {
		if lc, ok := a.toolData.sgLcuuidToName[item.Local]; ok {
			local = lc
		} else {
			local = item.Local
		}
		localPortRange = item.LocalPortRange
		if rm, ok := a.toolData.sgLcuuidToName[item.Remote]; ok {
			remote = rm
		} else {
			remote = item.Remote
		}
		remotePortRange = item.RemotePortRange
	}
	d["LOCAL"] = local
	d["LOCAL_PORT_RANGE"] = localPortRange
	d["REMOTE"] = remote
	d["REMOTE_PORT_RANGE"] = remotePortRange
	return d
}

type securityGroupRuleToolData struct {
	sgRules []mysql.SecurityGroupRule

	sgIDToName     map[int]string
	sgLcuuidToName map[string]string
}

func (td *securityGroupRuleToolData) Init() *securityGroupRuleToolData {
	td.sgIDToName = make(map[int]string)
	td.sgLcuuidToName = make(map[string]string)
	return td
}

func (td *securityGroupRuleToolData) Load() error {
	var err error
	td.sgRules, err = GetAll[mysql.SecurityGroupRule]()
	if err != nil {
		return err
	}

	sgs, err := Select[mysql.SecurityGroup]([]string{"id", "lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, sg := range sgs {
		td.sgIDToName[sg.ID] = sg.Name
		td.sgLcuuidToName[sg.Lcuuid] = sg.Name
	}
	return nil
}
