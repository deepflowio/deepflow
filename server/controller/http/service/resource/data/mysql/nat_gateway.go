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
	"strings"

	ctrlrcommon "github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/common"
)

type NATGateway struct {
	DataProvider
	toolData *natGatewayToolData
}

func NewNATGateway() *NATGateway {
	dp := &NATGateway{newDataProvider(ctrlrcommon.RESOURCE_TYPE_NAT_GATEWAY_EN), new(natGatewayToolData)}
	dp.setGenerator(dp)
	return dp
}

func (p *NATGateway) generate() ([]common.ResponseElem, error) {
	data := make([]common.ResponseElem, 0)
	err := p.toolData.Init().Load()
	if err != nil {
		return data, err
	}
	for _, item := range p.toolData.natGateways {
		data = append(data, p.generateOne(item))
	}
	return data, nil
}

func (a *NATGateway) generateOne(item mysql.NATGateway) common.ResponseElem {
	d := MySQLModelToMap(item)
	d["REGION_NAME"] = a.toolData.regionLcuuidToName[item.Region]
	d["DOMAIN_NAME"] = a.toolData.domainLcuuidToName[item.Domain]
	d["EPC_NAME"] = a.toolData.vpcIDToName[item.VPCID]
	d["WAN_IPS"] = strings.Split(item.FloatingIPs, ",")
	d["NAT_RULE_COUNT"] = a.toolData.ngIDToRuleCount[item.ID]

	d["CREATED_AT"] = item.CreatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	d["UPDATED_AT"] = item.UpdatedAt.Format(ctrlrcommon.GO_BIRTHDAY)
	return d
}

type natGatewayToolData struct {
	natGateways []mysql.NATGateway

	domainLcuuidToName map[string]string
	regionLcuuidToName map[string]string
	vpcIDToName        map[int]string

	ngIDToRuleCount map[int]int
}

func (td *natGatewayToolData) Init() *natGatewayToolData {
	td.domainLcuuidToName = make(map[string]string)
	td.regionLcuuidToName = make(map[string]string)
	td.vpcIDToName = make(map[int]string)

	td.ngIDToRuleCount = make(map[int]int)
	return td
}

func (td *natGatewayToolData) Load() error {
	var err error
	td.natGateways, err = GetAll[mysql.NATGateway]()
	if err != nil {
		return err
	}

	domains, err := Select[mysql.Domain]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range domains {
		td.domainLcuuidToName[item.Lcuuid] = item.Name
	}

	regions, err := Select[mysql.Region]([]string{"lcuuid", "name"})
	if err != nil {
		return err
	}
	for _, item := range regions {
		td.regionLcuuidToName[item.Lcuuid] = item.Name
	}

	vpcs, err := Select[mysql.VPC]([]string{"id", "name"})
	if err != nil {
		return err
	}
	for _, item := range vpcs {
		td.vpcIDToName[item.ID] = item.Name
	}

	natRules, err := Select[mysql.NATRule]([]string{"nat_id"})
	if err != nil {
		return err
	}
	for _, item := range natRules {
		td.ngIDToRuleCount[item.NATGatewayID]++
	}
	return nil
}
