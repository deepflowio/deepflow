/*
 * Copyright (c) 2022 Yunshan SecurityGroups
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

package huawei

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bitly/go-simplejson"
	. "github.com/deepflowys/deepflow/server/controller/cloud/huawei/common"
	"github.com/deepflowys/deepflow/server/controller/cloud/model"
	"github.com/deepflowys/deepflow/server/controller/common"
)

const (
	SECURITY_GROUP_RULE_ACCEPT  = 1
	SECURITY_GROUP_RULE_DROP    = 2
	SECURITY_GROUP_RULE_INGRESS = 1
	SECURITY_GROUP_RULE_EGRESS  = 2
	SECURITY_GROUP_IPV4         = 1
	SECURITY_GROUP_IPV6         = 2

	PORT_RANGE_ALL           = "0-65535"
	PROTOCOL_ALL             = "ALL"
	SUBNET_DEFAULT_CIDR_IPV4 = "0.0.0.0/0"
	SUBNET_DEFAULT_CIDR_IPV6 = "::/0"
)

func (h *HuaWei) getSecurityGroups() ([]model.SecurityGroup, []model.SecurityGroupRule, error) {
	var securityGroups []model.SecurityGroup
	var sgRules []model.SecurityGroupRule
	for project, token := range h.projectTokenMap {
		jSecurityGroups, err := h.getRawData(
			fmt.Sprintf("https://vpc.%s.%s/v1/%s/security-groups", project.name, h.config.URLDomain, project.id), token.token, "security_groups",
		)
		if err != nil {
			log.Errorf("request failed: %v", err)
			return nil, nil, err
		}

		regionLcuuid := h.projectNameToRegionLcuuid(project.name)
		for i := range jSecurityGroups {
			jSG := jSecurityGroups[i]
			if !CheckAttributes(jSG, []string{"id", "name"}) {
				continue
			}
			id := jSG.Get("id").MustString()
			name := jSG.Get("name").MustString()
			securityGroups = append(
				securityGroups,
				model.SecurityGroup{
					Lcuuid:       id,
					Name:         name,
					RegionLcuuid: regionLcuuid,
				},
			)
			h.toolDataSet.regionLcuuidToResourceNum[regionLcuuid]++
			h.toolDataSet.keyToSecurityGroupLcuuid[ProjectSecurityGroupKey{project.id, name}] = id

			jRules, ok := jSG.CheckGet("security_group_rules")
			if ok {
				sgRules = append(sgRules, h.formatSecurityGroupRules(jRules, id)...)
			}
		}
	}
	return securityGroups, sgRules, nil
}

func (h *HuaWei) formatSecurityGroupRules(jRules *simplejson.Json, sgLcuuid string) []model.SecurityGroupRule {
	var rules []model.SecurityGroupRule
	var ingressPriority, egressPriority int
	requiredAttrs := []string{"id", "direction", "ethertype", "protocol", "port_range_max", "port_range_max", "port_range_min", "remote_group_id", "remote_ip_prefix"}
	for i := range jRules.MustArray() {
		jRule := jRules.GetIndex(i)
		if !CheckAttributes(jRule, requiredAttrs) {
			continue
		}
		id := jRule.Get("id").MustString()
		rule := model.SecurityGroupRule{
			Lcuuid:              id,
			SecurityGroupLcuuid: sgLcuuid,
			LocalPortRange:      PORT_RANGE_ALL,
			Action:              SECURITY_GROUP_RULE_ACCEPT,
		}

		var local, remote string
		etherType := jRule.Get("ethertype").MustString()
		if etherType == "IPv6" {
			rule.EtherType = SECURITY_GROUP_IPV6
			local = SUBNET_DEFAULT_CIDR_IPV6
			remote = SUBNET_DEFAULT_CIDR_IPV6
		} else {
			rule.EtherType = SECURITY_GROUP_IPV4
			local = SUBNET_DEFAULT_CIDR_IPV4
			remote = SUBNET_DEFAULT_CIDR_IPV4
		}

		remoteGID := jRule.Get("remote_group_id").MustString()
		remoteIP := jRule.Get("remote_ip_prefix").MustString()
		if remoteIP != "" {
			remote = remoteIP
		} else if remoteGID != "" {
			remote = remoteGID
		}

		direction := jRule.Get("direction").MustString()
		if direction == "ingress" {
			rule.Direction = SECURITY_GROUP_RULE_INGRESS
			rule.Priority = ingressPriority
			local, remote = remote, local
			ingressPriority++
		} else {
			rule.Direction = SECURITY_GROUP_RULE_EGRESS
			rule.Priority = egressPriority
			egressPriority++
		}
		rule.Local = local
		rule.Remote = remote

		protocol := jRule.Get("protocol").MustString()
		if protocol != "" {
			rule.Protocol = strings.ToUpper(protocol)
		} else {
			rule.Protocol = PROTOCOL_ALL
		}

		minPort := jRule.Get("port_range_min").MustInt()
		maxPort := jRule.Get("port_range_max").MustInt()
		if minPort != 0 && maxPort != 0 {
			rule.RemotePortRange = fmt.Sprintf("%d-%d", minPort, maxPort)
		} else {
			rule.RemotePortRange = PORT_RANGE_ALL
		}

		rules = append(rules, rule)
	}

	directions := []int{SECURITY_GROUP_RULE_EGRESS, SECURITY_GROUP_RULE_INGRESS}
	etherTypeToRemote := map[int]string{SECURITY_GROUP_IPV4: SUBNET_DEFAULT_CIDR_IPV4, SECURITY_GROUP_IPV6: SUBNET_DEFAULT_CIDR_IPV6}
	for _, direction := range directions {
		for etherType, remote := range etherTypeToRemote {
			rule := model.SecurityGroupRule{
				Lcuuid:              common.GenerateUUID(sgLcuuid + strconv.Itoa(direction) + remote),
				SecurityGroupLcuuid: sgLcuuid,
				Action:              SECURITY_GROUP_RULE_DROP,
				Direction:           direction,
				EtherType:           etherType,
				Protocol:            PROTOCOL_ALL,
				Local:               remote,
				Remote:              remote,
				LocalPortRange:      PORT_RANGE_ALL,
				RemotePortRange:     PORT_RANGE_ALL,
				Priority:            1000,
			}
			rules = append(rules, rule)
		}
	}
	return rules
}
