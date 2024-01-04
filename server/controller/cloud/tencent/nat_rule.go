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

package tencent

import (
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/satori/go.uuid"
)

func (t *Tencent) getNatRules(region tencentRegion) ([]model.NATRule, error) {
	log.Debug("get nat rules starting")
	var natRules []model.NATRule

	if len(t.natIDs) == 0 {
		log.Debug("not found nat gateway ids")
		return []model.NATRule{}, nil
	}

	attrs := []string{"IpProtocol", "PublicIpAddress", "PublicPort", "PrivateIpAddress", "PrivatePort"}

	params := map[string]interface{}{
		"NatGatewayIds": t.natIDs,
	}

	resp, err := t.getResponse("vpc", "2017-03-12", "DescribeNatGatewayDestinationIpPortTranslationNatRules", region.name, "NatGatewayDestinationIpPortTranslationNatRuleSet", true, params)
	if err != nil {
		log.Errorf("nat rule request tencent api error: (%s)", err.Error())
		return []model.NATRule{}, err
	}
	for _, nData := range resp {
		if !t.checkRequiredAttributes(nData, attrs) {
			continue
		}
		natID := nData.Get("NatGatewayId").MustString()
		ipProtocol := nData.Get("IpProtocol").MustString()
		publicIP := nData.Get("PublicIpAddress").MustString()
		publicPort := nData.Get("PublicPort").MustInt()
		privateIP := nData.Get("PrivateIpAddress").MustString()
		privatePort := nData.Get("PrivatePort").MustInt()
		key := publicIP + natID + strconv.Itoa(publicPort) + ipProtocol + privateIP + strconv.Itoa(privatePort)
		natRules = append(natRules, model.NATRule{
			Lcuuid:           common.GetUUID(key, uuid.Nil),
			NATGatewayLcuuid: common.GetUUID(natID, uuid.Nil),
			Type:             "DNAT",
			Protocol:         strings.ToUpper(ipProtocol),
			FloatingIP:       publicIP,
			FloatingIPPort:   publicPort,
			FixedIP:          privateIP,
			FixedIPPort:      privatePort,
		})
	}
	log.Debug("get nat rules complete")
	return natRules, nil
}
