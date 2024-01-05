/*
 * Copyright (c) 2024 Yunshan SecurityGroups
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
	cloudcommon "github.com/deepflowio/deepflow/server/controller/cloud/common"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (h *HuaWei) getSecurityGroups() ([]model.SecurityGroup, []model.SecurityGroupRule, error) {
	var securityGroups []model.SecurityGroup
	var sgRules []model.SecurityGroupRule
	for project, token := range h.projectTokenMap {
		jSecurityGroups, err := h.getRawData(newRawDataGetContext(
			fmt.Sprintf("https://vpc.%s.%s/v1/%s/security-groups", project.name, h.config.Domain, project.id), token.token, "security_groups", pageQueryMethodMarker,
		))
		if err != nil {
			return nil, nil, err
		}

		regionLcuuid := h.projectNameToRegionLcuuid(project.name)
		for i := range jSecurityGroups {
			jSG := jSecurityGroups[i]
			id := jSG.Get("id").MustString()
			name := jSG.Get("name").MustString()
			if !cloudcommon.CheckJsonAttributes(jSG, []string{"id", "name"}) {
				log.Infof("exclude security_group: %s, missing attr", name)
				continue
			}
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
		id := jRule.Get("id").MustString()
		if !cloudcommon.CheckJsonAttributes(jRule, requiredAttrs) {
			log.Infof("exclude security_group_rule: %s, missing attr", id)
			continue
		}
		rule := model.SecurityGroupRule{
			Lcuuid:              id,
			SecurityGroupLcuuid: sgLcuuid,
			LocalPortRange:      cloudcommon.PORT_RANGE_ALL,
			Action:              cloudcommon.SECURITY_GROUP_RULE_ACCEPT,
		}

		var local, remote string
		etherType := jRule.Get("ethertype").MustString()
		if etherType == "IPv6" {
			rule.EtherType = cloudcommon.SECURITY_GROUP_IPV6
			local = cloudcommon.SUBNET_DEFAULT_CIDR_IPV6
			remote = cloudcommon.SUBNET_DEFAULT_CIDR_IPV6
		} else {
			rule.EtherType = cloudcommon.SECURITY_GROUP_IPV4
			local = cloudcommon.SUBNET_DEFAULT_CIDR_IPV4
			remote = cloudcommon.SUBNET_DEFAULT_CIDR_IPV4
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
			rule.Direction = cloudcommon.SECURITY_GROUP_RULE_INGRESS
			rule.Priority = ingressPriority
			local, remote = remote, local
			ingressPriority++
		} else {
			rule.Direction = cloudcommon.SECURITY_GROUP_RULE_EGRESS
			rule.Priority = egressPriority
			egressPriority++
		}
		rule.Local = local
		rule.Remote = remote

		protocol := jRule.Get("protocol").MustString()
		if protocol != "" {
			rule.Protocol = strings.ToUpper(protocol)
		} else {
			rule.Protocol = cloudcommon.PROTOCOL_ALL
		}

		minPort := jRule.Get("port_range_min").MustInt()
		maxPort := jRule.Get("port_range_max").MustInt()
		if minPort != 0 && maxPort != 0 {
			rule.RemotePortRange = fmt.Sprintf("%d-%d", minPort, maxPort)
		} else {
			rule.RemotePortRange = cloudcommon.PORT_RANGE_ALL
		}

		rules = append(rules, rule)
	}

	directions := []int{cloudcommon.SECURITY_GROUP_RULE_EGRESS, cloudcommon.SECURITY_GROUP_RULE_INGRESS}
	etherTypeToRemote := map[int]string{cloudcommon.SECURITY_GROUP_IPV4: cloudcommon.SUBNET_DEFAULT_CIDR_IPV4, cloudcommon.SECURITY_GROUP_IPV6: cloudcommon.SUBNET_DEFAULT_CIDR_IPV6}
	for _, direction := range directions {
		for etherType, remote := range etherTypeToRemote {
			rule := model.SecurityGroupRule{
				Lcuuid:              common.GenerateUUID(sgLcuuid + strconv.Itoa(direction) + remote),
				SecurityGroupLcuuid: sgLcuuid,
				Action:              cloudcommon.SECURITY_GROUP_RULE_DROP,
				Direction:           direction,
				EtherType:           etherType,
				Protocol:            cloudcommon.PROTOCOL_ALL,
				Local:               remote,
				Remote:              remote,
				LocalPortRange:      cloudcommon.PORT_RANGE_ALL,
				RemotePortRange:     cloudcommon.PORT_RANGE_ALL,
				Priority:            1000,
			}
			rules = append(rules, rule)
		}
	}
	return rules
}
