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

package aliyun

import (
	"strconv"
	"strings"

	ecs "github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (a *Aliyun) getSecurityGroups(region model.Region) ([]model.SecurityGroup, []model.SecurityGroupRule, error) {
	var retSecurityGroups []model.SecurityGroup
	var retSecurityGroupRules []model.SecurityGroupRule

	log.Debug("get security_groups starting")
	request := ecs.CreateDescribeSecurityGroupsRequest()
	response, err := a.getSecurityGroupResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retSecurityGroups, retSecurityGroupRules, err
	}

	for _, r := range response {
		securityGroups, _ := r.Get("SecurityGroup").Array()
		for i := range securityGroups {
			securityGroup := r.Get("SecurityGroup").GetIndex(i)

			err := a.checkRequiredAttributes(
				securityGroup,
				[]string{"SecurityGroupId", "SecurityGroupName", "VpcId"},
			)
			if err != nil {
				continue
			}
			securityGroupId := securityGroup.Get("SecurityGroupId").MustString()
			securityGroupName := securityGroup.Get("SecurityGroupName").MustString()
			if securityGroupName == "" {
				securityGroupName = securityGroupId
			}
			vpcId := securityGroup.Get("VpcId").MustString()

			securityGroupLcuuid := common.GenerateUUIDByOrgID(a.orgID, securityGroupId)
			retSecurityGroup := model.SecurityGroup{
				Lcuuid:       securityGroupLcuuid,
				Name:         securityGroupName,
				VPCLcuuid:    common.GenerateUUIDByOrgID(a.orgID, vpcId),
				RegionLcuuid: a.getRegionLcuuid(region.Lcuuid),
			}
			retSecurityGroups = append(retSecurityGroups, retSecurityGroup)
			a.regionLcuuidToResourceNum[retSecurityGroup.RegionLcuuid]++

			// 安全组规则
			tmpRules, err := a.getSecurityGroupRules(region, securityGroupId)
			if err != nil {
				return []model.SecurityGroup{}, []model.SecurityGroupRule{}, err
			}
			retSecurityGroupRules = append(retSecurityGroupRules, tmpRules...)
		}
	}

	log.Debug("get security_groups complete")
	return retSecurityGroups, retSecurityGroupRules, nil
}

func (a *Aliyun) getSecurityGroupRules(region model.Region, securityGroupId string) ([]model.SecurityGroupRule, error) {
	var retSecurityGroupRules []model.SecurityGroupRule

	request := ecs.CreateDescribeSecurityGroupAttributeRequest()
	request.SecurityGroupId = securityGroupId
	Response, err := a.getSecurityGroupAttributeResponse(region.Label, request)
	if err != nil {
		return retSecurityGroupRules, err
	}

	securityGroupLcuuid := common.GenerateUUIDByOrgID(a.orgID, securityGroupId)
	for _, rRule := range Response {
		for j := range rRule.Get("Permission").MustArray() {
			rule := rRule.Get("Permission").GetIndex(j)

			err := a.checkRequiredAttributes(
				rule,
				[]string{
					"SourceCidrIp", "DestCidrIp", "PortRange", "Direction", "IpProtocol", "Policy",
				},
			)
			if err != nil {
				continue
			}

			local := common.SECURITY_GROUP_RULE_IPV4_CIDR
			remote := rule.Get("SourceCidrIp").MustString()
			ethertype := common.SECURITY_GROUP_RULE_IPV4
			direction := common.SECURITY_GROUP_RULE_INGRESS
			ruleDirection := rule.Get("Direction").MustString()
			if ruleDirection == "ingress" {
				if remote == "" {
					remote = rule.Get("Ipv6SourceCidrIp").MustString()
					if remote == "" {
						log.Debug("security rules not found remote address")
						continue
					}
					local = common.SECURITY_GROUP_RULE_IPV6_CIDR
					ethertype = common.SECURITY_GROUP_RULE_IPV6
				}
			} else {
				direction = common.SECURITY_GROUP_RULE_EGRESS
				destCidrIp := rule.Get("DestCidrIp").MustString()
				if destCidrIp == "" {
					destCidrIp = rule.Get("Ipv6DestCidrIp").MustString()
					local = common.SECURITY_GROUP_RULE_IPV6_CIDR
					ethertype = common.SECURITY_GROUP_RULE_IPV6
				}
				remote = destCidrIp
			}

			groupId := rule.Get("SourceGroupId").MustString()
			if groupId == "" {
				groupId = rule.Get("DestGroupId").MustString()
			}
			if groupId != "" {
				ethertype = common.SECURITY_GROUP_IP_TYPE_UNKNOWN
				remote = common.GenerateUUIDByOrgID(a.orgID, groupId)
			}
			if direction == common.SECURITY_GROUP_RULE_INGRESS {
				local, remote = remote, local
			}

			action := common.SECURITY_GROUP_RULE_ACCEPT
			if rule.Get("Policy").MustString() != "Accept" {
				action = common.SECURITY_GROUP_RULE_DROP
			}

			priority := rule.Get("Priority").MustInt()
			protocol := rule.Get("IpProtocol").MustString()
			portRange := rule.Get("PortRange").MustString()
			strings.Replace(portRange, "/", "-", -1)
			if portRange == "-1--1" {
				portRange = "0-65535"
			}

			key := securityGroupId + strconv.Itoa(direction) + local + remote + portRange +
				protocol + strconv.Itoa(priority) + strconv.Itoa(action)
			retRule := model.SecurityGroupRule{
				Lcuuid:              common.GenerateUUIDByOrgID(a.orgID, key),
				SecurityGroupLcuuid: securityGroupLcuuid,
				Direction:           direction,
				EtherType:           ethertype,
				Protocol:            protocol,
				LocalPortRange:      "0-65535",
				RemotePortRange:     portRange,
				Local:               local,
				Remote:              remote,
				Priority:            priority,
				Action:              action,
			}
			retSecurityGroupRules = append(retSecurityGroupRules, retRule)
		}
	}

	// 针对连通性检测，额外补充几条安全组规则
	for _, direction := range []int{
		common.SECURITY_GROUP_RULE_INGRESS, common.SECURITY_GROUP_RULE_EGRESS,
	} {
		for _, action := range []int{
			common.SECURITY_GROUP_RULE_DROP, common.SECURITY_GROUP_RULE_ACCEPT,
		} {
			if direction == common.SECURITY_GROUP_RULE_INGRESS && action == common.SECURITY_GROUP_RULE_ACCEPT {
				continue
			} else if direction == common.SECURITY_GROUP_RULE_EGRESS && action == common.SECURITY_GROUP_RULE_DROP {
				continue
			}
			for _, ethertype := range []int{
				common.SECURITY_GROUP_RULE_IPV4, common.SECURITY_GROUP_RULE_IPV6,
			} {
				local := common.SECURITY_GROUP_RULE_IPV4_CIDR
				remote := common.SECURITY_GROUP_RULE_IPV4_CIDR
				if ethertype == common.SECURITY_GROUP_RULE_IPV4 {
					local = common.SECURITY_GROUP_RULE_IPV6_CIDR
					remote = common.SECURITY_GROUP_RULE_IPV6_CIDR
				}
				key := securityGroupLcuuid + strconv.Itoa(direction) + local
				retRule := model.SecurityGroupRule{
					Lcuuid:              common.GenerateUUIDByOrgID(a.orgID, key),
					SecurityGroupLcuuid: securityGroupLcuuid,
					Direction:           direction,
					EtherType:           ethertype,
					Protocol:            "ALL",
					LocalPortRange:      "0-65535",
					RemotePortRange:     "0-65535",
					Local:               local,
					Remote:              remote,
					Priority:            1000,
					Action:              action,
				}
				retSecurityGroupRules = append(retSecurityGroupRules, retRule)
			}
		}
	}
	return retSecurityGroupRules, nil
}
