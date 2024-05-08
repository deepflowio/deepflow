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

package baidubce

import (
	"strconv"
	"strings"
	"time"

	"github.com/baidubce/bce-sdk-go/services/bcc"
	bcc_api "github.com/baidubce/bce-sdk-go/services/bcc/api"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (b *BaiduBce) getSecurityGroups(region model.Region, vpcIdToLcuuid map[string]string) (
	[]model.SecurityGroup, []model.SecurityGroupRule, error,
) {
	var retSecurityGroups []model.SecurityGroup
	var retSecurityGroupRules []model.SecurityGroupRule

	log.Debug("get security_groups starting")

	bccClient, _ := bcc.NewClient(b.secretID, b.secretKey, "bcc."+b.endpoint)
	bccClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	marker := ""
	args := &bcc_api.ListSecurityGroupArgs{}
	results := make([]*bcc_api.ListSecurityGroupResult, 0)
	for {
		args.Marker = marker
		startTime := time.Now()
		result, err := bccClient.ListSecurityGroup(args)
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}
		b.cloudStatsd.RefreshAPIMoniter("ListSecurityGroup", len(result.SecurityGroups), startTime)
		results = append(results, result)
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}

	b.debugger.WriteJson("ListSecurityGroup", " ", structToJson(results))
	for _, r := range results {
		for _, securityGroup := range r.SecurityGroups {
			vpcLcuuid, ok := vpcIdToLcuuid[securityGroup.VpcId]
			if !ok {
				log.Debugf("security_group (%s) vpc (%s) not found", securityGroup.Id, securityGroup.VpcId)
				continue
			}
			securityGroupLcuuid := common.GenerateUUIDByOrgID(b.orgID, securityGroup.Id)
			retSecurityGroup := model.SecurityGroup{
				Lcuuid:       securityGroupLcuuid,
				Name:         securityGroup.Name,
				VPCLcuuid:    vpcLcuuid,
				RegionLcuuid: region.Lcuuid,
			}
			retSecurityGroups = append(retSecurityGroups, retSecurityGroup)
			b.regionLcuuidToResourceNum[retSecurityGroup.RegionLcuuid]++

			// 安全组规则
			inBoundRuleIndex := 0
			outBoundRuleIndex := 0
			for _, rule := range securityGroup.Rules {
				ethertype := common.SECURITY_GROUP_RULE_IPV4
				local := common.SECURITY_GROUP_RULE_IPV4_CIDR
				remote := ""
				remoteAll := common.SECURITY_GROUP_RULE_IPV4_CIDR
				if rule.Ethertype != "IPv4" {
					ethertype = common.SECURITY_GROUP_RULE_IPV6
					local = common.SECURITY_GROUP_RULE_IPV6_CIDR
					remoteAll = common.SECURITY_GROUP_RULE_IPV6_CIDR
				}

				direction := common.SECURITY_GROUP_RULE_INGRESS
				ruleIndex := 0
				if rule.Direction != "ingress" {
					direction = common.SECURITY_GROUP_RULE_EGRESS
					outBoundRuleIndex += 1
					ruleIndex = outBoundRuleIndex
					remote = rule.DestIp
					// 暂不支持对接远端为安全组的规则
					if remote == "" {
						continue
					} else if remote == "all" {
						remote = remoteAll
					}
				} else {
					inBoundRuleIndex += 1
					ruleIndex = inBoundRuleIndex
					remote = rule.SourceIp
					// 暂不支持对接远端为安全组的规则
					if remote == "" {
						continue
					} else if remote == "all" {
						remote = remoteAll
					}
					local, remote = remote, local
				}

				ruleLcuuid := common.GenerateUUIDByOrgID(b.orgID, securityGroupLcuuid+strconv.Itoa(direction)+local+remote+rule.Protocol+rule.PortRange+strconv.Itoa(ruleIndex))
				retRule := model.SecurityGroupRule{
					Lcuuid:              ruleLcuuid,
					SecurityGroupLcuuid: securityGroupLcuuid,
					Direction:           direction,
					Protocol:            strings.ToUpper(rule.Protocol),
					EtherType:           ethertype,
					LocalPortRange:      "1-65535",
					RemotePortRange:     rule.PortRange,
					Local:               local,
					Remote:              remote,
					Priority:            ruleIndex,
					Action:              common.SECURITY_GROUP_RULE_ACCEPT,
				}
				retSecurityGroupRules = append(retSecurityGroupRules, retRule)
			}
			// 默认添加入/出方向deny all规则
			for _, direction := range []int{
				common.SECURITY_GROUP_RULE_INGRESS,
				common.SECURITY_GROUP_RULE_EGRESS,
			} {
				for _, ethertype := range []int{
					common.SECURITY_GROUP_RULE_IPV4,
					common.SECURITY_GROUP_RULE_IPV6,
				} {
					remote := common.SECURITY_GROUP_RULE_IPV4_CIDR
					if ethertype != common.SECURITY_GROUP_RULE_IPV4 {
						remote = common.SECURITY_GROUP_RULE_IPV6_CIDR
					}
					retRule := model.SecurityGroupRule{
						Lcuuid:              common.GenerateUUIDByOrgID(b.orgID, securityGroupLcuuid+strconv.Itoa(direction)+remote),
						SecurityGroupLcuuid: securityGroupLcuuid,
						Direction:           direction,
						EtherType:           ethertype,
						Protocol:            "ALL",
						LocalPortRange:      "1-65535",
						RemotePortRange:     "1-65535",
						Local:               remote,
						Remote:              remote,
						Priority:            1000,
						Action:              common.SECURITY_GROUP_RULE_DROP,
					}
					retSecurityGroupRules = append(retSecurityGroupRules, retRule)
				}
			}
		}
	}

	log.Debug("get security_groups complete")
	return retSecurityGroups, retSecurityGroupRules, nil
}
