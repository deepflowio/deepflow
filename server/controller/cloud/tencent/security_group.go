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

	mapset "github.com/deckarep/golang-set"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (t *Tencent) analysisProtocolPort(region tencentRegion, serviceID ...string) mapset.Set {
	serviceSet := mapset.NewSet()

	if len(serviceID) == 0 {
		return mapset.NewSet()
	}

	filters := map[string]interface{}{
		"Name":   "service-template-id",
		"Values": serviceID,
	}
	resp, err := t.getResponse("vpc", "2017-03-12", "DescribeServiceTemplates", region.name, "ServiceTemplateSet", true, map[string]interface{}{}, filters)
	if err != nil {
		log.Errorf("security group service templates request tencent api error: (%s)", err.Error())
		return mapset.NewSet()
	}
	for _, data := range resp {
		services := data.Get("ServiceSet")
		for s := range services.MustArray() {
			service := services.GetIndex(s).MustString()
			if !strings.Contains(service, ":") {
				log.Warningf("security group service templates (%s) format error", service)
				continue
			}
			serviceSlice := strings.Split(service, ":")
			serviceSet.Add(tencentProtocolPort{
				protocol: strings.ToUpper(serviceSlice[0]),
				port:     serviceSlice[1],
			})
		}
	}

	return serviceSet
}

func (t *Tencent) analysisIPAddress(region tencentRegion, addressID ...string) mapset.Set {
	addressSet := mapset.NewSet()

	if len(addressID) == 0 {
		return mapset.NewSet()
	}

	filters := map[string]interface{}{
		"Name":   "address-template-id",
		"Values": addressID,
	}
	resp, err := t.getResponse("vpc", "2017-03-12", "DescribeAddressTemplates", region.name, "AddressTemplateSet", true, map[string]interface{}{}, filters)
	if err != nil {
		log.Errorf("security group address templates request tencent api error: (%s)", err.Error())
		return mapset.NewSet()
	}
	for _, data := range resp {
		addresses := data.Get("AddressSet")
		for s := range addresses.MustArray() {
			addressSet.Add(addresses.GetIndex(s).MustString())
		}
	}
	return addressSet
}

func (t *Tencent) getSecurityGroups(region tencentRegion) ([]model.SecurityGroup, []model.SecurityGroupRule, error) {
	log.Debug("get security groups starting")
	var sgs []model.SecurityGroup
	var sgRules []model.SecurityGroupRule

	sgAttrs := []string{"SecurityGroupId", "SecurityGroupName"}
	ruleAttrs := []string{"PolicyIndex", "Port", "Action"}
	sgResp, err := t.getResponse("vpc", "2017-03-12", "DescribeSecurityGroups", region.name, "SecurityGroupSet", true, map[string]interface{}{})
	if err != nil {
		log.Errorf("security group request tencent api error: (%s)", err.Error())
		return []model.SecurityGroup{}, []model.SecurityGroupRule{}, err
	}
	for _, sData := range sgResp {
		if !t.checkRequiredAttributes(sData, sgAttrs) {
			continue
		}
		sgID := sData.Get("SecurityGroupId").MustString()
		sgLcuuid := common.GetUUIDByOrgID(t.orgID, sgID)
		sgs = append(sgs, model.SecurityGroup{
			Lcuuid:       sgLcuuid,
			Name:         sData.Get("SecurityGroupName").MustString(),
			RegionLcuuid: t.getRegionLcuuid(region.lcuuid),
		})

		ruleSlice := []tencentGressRule{}
		params := map[string]interface{}{
			"SecurityGroupId": sgID,
		}
		sgPolicyResp, err := t.getResponse("vpc", "2017-03-12", "DescribeSecurityGroupPolicies", region.name, "SecurityGroupPolicySet", false, params)
		if err != nil {
			log.Errorf("security group policy request tencent api error: (%s)", err.Error())
			return []model.SecurityGroup{}, []model.SecurityGroupRule{}, err
		}
		for _, sgPData := range sgPolicyResp {
			ingressRules := sgPData.Get("Ingress")
			for i := range ingressRules.MustArray() {
				ruleSlice = append(ruleSlice, tencentGressRule{
					direction: common.SECURITY_GROUP_RULE_INGRESS,
					rule:      ingressRules.GetIndex(i),
				})
			}
			egressRules := sgPData.Get("Egress")
			for r := range egressRules.MustArray() {
				ruleSlice = append(ruleSlice, tencentGressRule{
					direction: common.SECURITY_GROUP_RULE_EGRESS,
					rule:      egressRules.GetIndex(r),
				})
			}
		}
		for _, rule := range ruleSlice {
			if !t.checkRequiredAttributes(rule.rule, ruleAttrs) {
				continue
			}
			addressSet := mapset.NewSet()
			serviceSet := mapset.NewSet()
			protocol := rule.rule.Get("Protocol").MustString()
			etherType := common.SECURITY_GROUP_RULE_IPV4
			if protocol != "" {
				serviceSet.Add(tencentProtocolPort{
					port:     rule.rule.Get("Port").MustString(),
					protocol: strings.ToUpper(protocol),
				})
			}
			action := common.SECURITY_GROUP_RULE_ACCEPT
			if cidrBlock, ok := rule.rule.CheckGet("CidrBlock"); ok && cidrBlock.MustString() != "" {
				addressSet.Add(cidrBlock.MustString())
			}
			if cidrBlockV6, ok := rule.rule.CheckGet("Ipv6CidrBlock"); ok && cidrBlockV6.MustString() != "" {
				addressSet.Add(cidrBlockV6.MustString())
			}

			if rSGID, ok := rule.rule.CheckGet("SecurityGroupId"); ok && rSGID.MustString() != "" {
				etherType = common.SECURITY_GROUP_IP_TYPE_UNKNOWN
				addressSet.Add(common.GetUUIDByOrgID(t.orgID, rSGID.MustString()))
			}

			if rule.rule.Get("Action").MustString() != "ACCEPT" {
				action = common.SECURITY_GROUP_RULE_DROP
			}

			serviceID := rule.rule.Get("ServiceTemplate").Get("ServiceId").MustString()
			if serviceID != "" {
				services := t.analysisProtocolPort(region, serviceID)
				serviceSet = serviceSet.Union(services)
			}

			sGroupID := rule.rule.Get("ServiceTemplate").Get("ServiceGroupId").MustString()
			if sGroupID != "" {
				stIDs := []string{}
				sFilters := map[string]interface{}{
					"Name":   "service-template-group-id",
					"Values": []string{sGroupID},
				}
				stgResp, err := t.getResponse("vpc", "2017-03-12", "DescribeServiceTemplateGroups", region.name, "ServiceTemplateGroupSet", true, map[string]interface{}{}, sFilters)
				if err != nil {
					log.Errorf("security group service template groups request tencent api error: (%s)", err.Error())
					return []model.SecurityGroup{}, []model.SecurityGroupRule{}, err
				}
				for _, stgData := range stgResp {
					stgs := stgData.Get("ServiceTemplateIdSet")
					for s := range stgs.MustArray() {
						stg := stgs.GetIndex(s)
						stIDs = append(stIDs, stg.MustString())
					}
				}
				services := t.analysisProtocolPort(region, stIDs...)
				serviceSet = serviceSet.Union(services)
			}

			addressID := rule.rule.Get("AddressTemplate").Get("AddressId").MustString()
			if addressID != "" {
				addresses := t.analysisIPAddress(region, addressID)
				addressSet = addressSet.Union(addresses)
			}

			aGroupID := rule.rule.Get("AddressTemplate").Get("AddressGroupId").MustString()
			if aGroupID != "" {
				atIDs := []string{}
				aFilters := map[string]interface{}{
					"Name":   "address-template-group-id",
					"Values": []string{aGroupID},
				}
				atgResp, err := t.getResponse("vpc", "2017-03-12", "DescribeAddressTemplateGroups", region.name, "AddressTemplateGroupSet", true, map[string]interface{}{}, aFilters)
				if err != nil {
					log.Errorf("security group address template groups request tencent api error: (%s)", err.Error())
					return []model.SecurityGroup{}, []model.SecurityGroupRule{}, err
				}
				for _, atgData := range atgResp {
					atgs := atgData.Get("AddressTemplateIdSet")
					for a := range atgs.MustArray() {
						atg := atgs.GetIndex(a)
						atIDs = append(atIDs, atg.MustString())
					}
				}
				addresses := t.analysisIPAddress(region, atIDs...)
				addressSet = addressSet.Union(addresses)
			}
			for _, s := range serviceSet.ToSlice() {
				for _, a := range addressSet.ToSlice() {
					local := common.SECURITY_GROUP_RULE_IPV6_CIDR
					if etherType == common.SECURITY_GROUP_RULE_IPV4 {
						local = common.SECURITY_GROUP_RULE_IPV4_CIDR
					}
					address := a.(string)
					if rule.direction == common.SECURITY_GROUP_RULE_INGRESS {
						local, address = address, local

					}
					policyIndex := rule.rule.Get("PolicyIndex").MustInt()
					remotePortRange := "0-65535"
					if strings.ToUpper(s.(tencentProtocolPort).port) != "ALL" {
						remotePortRange = s.(tencentProtocolPort).port
					}
					sgGenerateID := sgID + local + strconv.Itoa(policyIndex) + s.(tencentProtocolPort).protocol + "_" + s.(tencentProtocolPort).port + address + strconv.Itoa(action) + "_" + strconv.Itoa(rule.direction)
					sgRules = append(sgRules, model.SecurityGroupRule{
						Lcuuid:              common.GetUUIDByOrgID(t.orgID, sgGenerateID),
						SecurityGroupLcuuid: sgLcuuid,
						Direction:           rule.direction,
						Protocol:            s.(tencentProtocolPort).protocol,
						EtherType:           etherType,
						LocalPortRange:      "0-65535",
						RemotePortRange:     remotePortRange,
						Local:               local,
						Remote:              address,
						Priority:            policyIndex,
						Action:              action,
					})
				}
			}
		}
		for _, d := range []int{common.SECURITY_GROUP_RULE_INGRESS, common.SECURITY_GROUP_RULE_EGRESS} {
			for _, e := range []int{common.SECURITY_GROUP_RULE_IPV4, common.SECURITY_GROUP_RULE_IPV6} {
				remote := common.SECURITY_GROUP_RULE_IPV6_CIDR
				if e == common.SECURITY_GROUP_RULE_IPV4 {
					remote = common.SECURITY_GROUP_RULE_IPV4_CIDR
				}
				sgRules = append(sgRules, model.SecurityGroupRule{
					Lcuuid:              common.GetUUIDByOrgID(t.orgID, sgLcuuid+strconv.Itoa(d)+remote),
					SecurityGroupLcuuid: sgLcuuid,
					Direction:           d,
					EtherType:           e,
					Protocol:            "ALL",
					LocalPortRange:      "0-65535",
					RemotePortRange:     "0-65535",
					Local:               remote,
					Remote:              remote,
					Priority:            1000,
					Action:              common.SECURITY_GROUP_RULE_DROP,
				})
			}
		}
	}
	log.Debug("get security groups complete")
	return sgs, sgRules, nil
}
