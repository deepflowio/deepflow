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

const (
	NAT_RULE_TYPE_SNAT   = "SNAT"
	NAT_RULE_PORT_ALL    = "ALL"
	NAT_RULE_NAT_ID_NONE = 0
)

type NATRule struct {
	DataProvider
	toolData *natRuleToolData
}

func NewNATRule() *NATRule {
	dp := &NATRule{newDataProvider(ctrlrcommon.RESOURCE_TYPE_NAT_RULE_EN), new(natRuleToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *NATRule) generate() ([]common.ResponseElem, error) {
	data := make([]common.ResponseElem, 0)
	err := p.toolData.Init().Load()
	if err != nil {
		return data, err
	}
	for _, item := range p.toolData.natRules {
		data = append(data, p.generateOne(item))
	}
	return data, nil
}

func (a *NATRule) generateOne(item mysql.NATRule) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["EPC_ID"] = a.toolData.natGatewayIDToVPCID[item.NATGatewayID]
	d["NAT_GATEWAY_NAME"] = a.toolData.natGatewayIDToName[item.NATGatewayID]
	if item.FixedIPPort == 0 { // TODO change to pointer in mysql model?
		d["FIXED_IP_PORT"] = nil
	}
	if item.FloatingIPPort == 0 {
		d["FLOATING_IP_PORT"] = nil
	}
	var beforeIP, afterIP string
	var beforePort, afterPort int
	if item.Type == NAT_RULE_TYPE_SNAT {
		beforeIP = item.FixedIP
		afterIP = item.FloatingIP
		beforePort = item.FixedIPPort
		afterPort = item.FloatingIPPort
	} else {
		beforeIP = item.FloatingIP
		afterIP = item.FixedIP
		beforePort = item.FloatingIPPort
		afterPort = item.FixedIPPort
	}
	d["NAT_BEFORE_IP"] = beforeIP
	d["NAT_AFTER_IP"] = afterIP
	if beforePort != 0 {
		d["NAT_BEFORE_PORT"] = beforePort
	} else {
		d["NAT_BEFORE_PORT"] = NAT_RULE_PORT_ALL
	}
	if afterPort != 0 {
		d["NAT_AFTER_PORT"] = afterPort
	} else {
		d["NAT_AFTER_PORT"] = NAT_RULE_PORT_ALL
	}
	return d
}

type natRuleToolData struct {
	natRules []mysql.NATRule

	natGatewayIDToVPCID map[int]int
	natGatewayIDToName  map[int]string
}

func (td *natRuleToolData) Init() *natRuleToolData {
	td.natGatewayIDToVPCID = make(map[int]int)
	td.natGatewayIDToName = make(map[int]string)
	return td
}

func (td *natRuleToolData) Load() error {
	var err error
	td.natRules, err = FindWhereObj[mysql.NATRule]("nat_id != ?", NAT_RULE_NAT_ID_NONE)
	if err != nil {
		return err
	}

	ngs, err := Select[mysql.NATGateway]([]string{"id", "epc_id", "name"})
	if err != nil {
		return err
	}
	for _, item := range ngs {
		td.natGatewayIDToVPCID[item.ID] = item.VPCID
		td.natGatewayIDToName[item.ID] = item.Name
	}
	return nil
}
