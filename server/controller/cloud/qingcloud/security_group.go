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

package qingcloud

import (
	"strconv"
	"strings"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (q *QingCloud) GetSecurityGroups() ([]model.SecurityGroup, []model.SecurityGroupRule, error) {
	var retSecurityGroups []model.SecurityGroup
	var retSecurityGroupRules []model.SecurityGroupRule

	log.Info("get security_groups starting")

	for regionId, regionLcuuid := range q.RegionIdToLcuuid {
		kwargs := []*Param{{"zone", regionId}}
		response, err := q.GetResponse("DescribeSecurityGroups", "security_group_set", kwargs)
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}

		for _, r := range response {
			for i := range r.MustArray() {
				securityGroup := r.GetIndex(i)
				err := q.CheckRequiredAttributes(securityGroup, []string{
					"security_group_id", "security_group_name",
				})
				if err != nil {
					continue
				}

				securityGroupId := securityGroup.Get("security_group_id").MustString()
				securityGroupName := securityGroup.Get("security_group_name").MustString()
				if securityGroupName == "" {
					securityGroupName = securityGroupId
				}
				securityGroupLcuuid := common.GenerateUUIDByOrgID(q.orgID, securityGroupId)
				retSecurityGroups = append(retSecurityGroups, model.SecurityGroup{
					Lcuuid:       securityGroupLcuuid,
					Name:         securityGroupName,
					Label:        securityGroupId,
					RegionLcuuid: regionLcuuid,
				})
				q.regionLcuuidToResourceNum[regionLcuuid]++

				// 针对每个安全组生成入出两个方向的默认规则
				for direction, action := range map[int]int{
					common.SECURITY_GROUP_RULE_INGRESS: common.SECURITY_GROUP_RULE_DROP,
					common.SECURITY_GROUP_RULE_EGRESS:  common.SECURITY_GROUP_RULE_ACCEPT,
				} {
					for _, ethertype := range []int{
						common.SECURITY_GROUP_RULE_IPV4, common.SECURITY_GROUP_RULE_IPV6,
					} {
						remote := common.SECURITY_GROUP_RULE_IPV4_CIDR
						if ethertype == common.SECURITY_GROUP_RULE_IPV6 {
							remote = common.SECURITY_GROUP_RULE_IPV6_CIDR
						}
						retSecurityGroupRules = append(
							retSecurityGroupRules,
							model.SecurityGroupRule{
								Lcuuid:              common.GenerateUUIDByOrgID(q.orgID, securityGroupLcuuid+strconv.Itoa(direction)+remote),
								SecurityGroupLcuuid: securityGroupLcuuid,
								Direction:           direction,
								EtherType:           ethertype,
								Protocol:            "ALL",
								LocalPortRange:      "0-65535",
								RemotePortRange:     "0-65535",
								Local:               remote,
								Remote:              remote,
								Priority:            1000,
								Action:              action,
							},
						)
					}
				}
			}
		}
	}

	tmpSecurityGroupRules, err := q.getSecurityGroupRules()
	if err != nil {
		return nil, nil, err
	}
	retSecurityGroupRules = append(retSecurityGroupRules, tmpSecurityGroupRules...)

	log.Info("get security_groups complete")
	return retSecurityGroups, retSecurityGroupRules, nil
}

func (q *QingCloud) getSecurityGroupRules() ([]model.SecurityGroupRule, error) {
	var retSecurityGroupRules []model.SecurityGroupRule

	log.Info("get security_group rules starting")

	for regionId := range q.RegionIdToLcuuid {
		kwargs := []*Param{{"zone", regionId}}
		response, err := q.GetResponse(
			"DescribeSecurityGroupIPSets", "security_group_ipset_set", kwargs,
		)
		if err != nil {
			log.Error(err)
			return nil, err
		}

		idToIPSet := make(map[string]string)
		for _, r := range response {
			for i := range r.MustArray() {
				ipSet := r.GetIndex(i)
				idToIPSet[ipSet.Get("security_group_ipset_id").MustString()] =
					ipSet.Get("val").MustString()
			}
		}

		// 获取安全组规则
		response, err = q.GetResponse(
			"DescribeSecurityGroupRules", "security_group_rule_set", kwargs,
		)
		if err != nil {
			log.Error(err)
			return nil, nil
		}

		for _, r := range response {
			for i := range r.MustArray() {
				rule := r.GetIndex(i)
				err := q.CheckRequiredAttributes(rule, []string{
					"disabled", "direction", "protocol", "security_group_id", "priority",
					"security_group_rule_id", "action",
				})
				if err != nil {
					continue
				}

				direction := common.SECURITY_GROUP_RULE_INGRESS
				if rule.Get("direction").MustInt() != 0 {
					direction = common.SECURITY_GROUP_RULE_EGRESS
				}
				protocol := strings.ToUpper(rule.Get("protocol").MustString())
				// 获取portRange
				portRange := "0-65535"
				if protocol == "TCP" || protocol == "UDP" {
					val1 := rule.Get("val1").MustString()
					ipSet, ok := idToIPSet[val1]
					if !ok {
						srcPort := "0"
						if val1 != "" {
							srcPort = val1
						}
						dstPort := "65535"
						if rule.Get("val2").MustString() != "" {
							dstPort = rule.Get("val2").MustString()
						}
						portRange = srcPort + "-" + dstPort
					} else {
						portRange = ipSet
					}
				}
				// 获取local和remote
				ethertype := common.SECURITY_GROUP_RULE_IPV4
				local := common.SECURITY_GROUP_RULE_IPV4_CIDR
				remote := common.SECURITY_GROUP_RULE_IPV4_CIDR
				if strings.Contains(protocol, "IPV6") {
					ethertype = common.SECURITY_GROUP_RULE_IPV6
					local = common.SECURITY_GROUP_RULE_IPV6_CIDR
					remote = common.SECURITY_GROUP_RULE_IPV6_CIDR
				}
				val3 := rule.Get("val3").MustString()
				if val3 != "" {
					if ipSet, ok := idToIPSet[val3]; ok {
						remote = ipSet
					} else {
						remote = val3
					}
				}
				if direction == common.SECURITY_GROUP_RULE_INGRESS {
					local, remote = remote, local
				}

				ruleId := rule.Get("security_group_rule_id").MustString()
				securityGroupId := rule.Get("security_group_id").MustString()
				retSecurityGroupRules = append(
					retSecurityGroupRules,
					model.SecurityGroupRule{
						Lcuuid:              common.GenerateUUIDByOrgID(q.orgID, ruleId),
						SecurityGroupLcuuid: common.GenerateUUIDByOrgID(q.orgID, securityGroupId),
						Direction:           direction,
						EtherType:           ethertype,
						Protocol:            protocol,
						LocalPortRange:      "0-65535",
						RemotePortRange:     portRange,
						Local:               local,
						Remote:              remote,
						Priority:            rule.Get("priority").MustInt(),
						Action:              common.SECURITY_GROUP_RULE_ACCEPT,
					},
				)
			}
		}
	}
	log.Info("get security_group rules complete")
	return retSecurityGroupRules, nil
}
