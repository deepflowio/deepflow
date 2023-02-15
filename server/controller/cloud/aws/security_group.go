/*
 * Copyright (c) 2022 Yunshan Networks
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

package aws

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	uuid "github.com/satori/go.uuid"
)

func (a *Aws) getSecurityGroups(region awsRegion) ([]model.SecurityGroup, []model.SecurityGroupRule, error) {
	log.Debug("get security groups starting")
	var sgs []model.SecurityGroup
	var sgRules []model.SecurityGroupRule

	var retSecurityGroups []types.SecurityGroup
	var nextToken string
	var maxResults int32 = 100
	for {
		var input *ec2.DescribeSecurityGroupsInput
		if nextToken == "" {
			input = &ec2.DescribeSecurityGroupsInput{MaxResults: &maxResults}
		} else {
			input = &ec2.DescribeSecurityGroupsInput{MaxResults: &maxResults, NextToken: &nextToken}
		}
		result, err := a.ec2Client.DescribeSecurityGroups(context.TODO(), input)
		if err != nil {
			log.Errorf("security group request aws api error: (%s)", err.Error())
			return []model.SecurityGroup{}, []model.SecurityGroupRule{}, err
		}
		retSecurityGroups = append(retSecurityGroups, result.SecurityGroups...)
		if result.NextToken == nil {
			break
		}
		nextToken = *result.NextToken
	}

	for _, sData := range retSecurityGroups {
		sgGroupID := a.getStringPointerValue(sData.GroupId)
		sgLcuuid := common.GetUUID(sgGroupID, uuid.Nil)
		sgName := a.getResultTagName(sData.Tags)
		if sgName == "" {
			sgName = a.getStringPointerValue(sData.GroupName)
		}
		sgs = append(sgs, model.SecurityGroup{
			Lcuuid:       sgLcuuid,
			Name:         sgName,
			VPCLcuuid:    common.GetUUID(a.getStringPointerValue(sData.VpcId), uuid.Nil),
			RegionLcuuid: a.getRegionLcuuid(region.lcuuid),
		})

		ruleSlice := []awsGressRule{}
		for i, iRule := range sData.IpPermissions {
			ruleSlice = append(ruleSlice, awsGressRule{
				rule:      iRule,
				priority:  i,
				direction: common.SECURITY_GROUP_RULE_INGRESS,
			})
		}
		for e, eRule := range sData.IpPermissionsEgress {
			ruleSlice = append(ruleSlice, awsGressRule{
				rule:      eRule,
				priority:  e,
				direction: common.SECURITY_GROUP_RULE_EGRESS,
			})
		}

		for _, r := range ruleSlice {
			protocol := strings.ToUpper(a.getStringPointerValue(r.rule.IpProtocol))
			if protocol == "-1" {
				protocol = "ALL"
			}
			if strings.HasSuffix(protocol, "V6") {
				log.Infof("security group rule protocol (%s) not support", protocol)
				continue
			}
			fromPort := a.getInt32PointerValue(r.rule.FromPort)
			if fromPort == -1 || fromPort == 0 {
				fromPort = 0
			}
			toPort := a.getInt32PointerValue(r.rule.ToPort)
			if toPort == -1 || toPort == 0 {
				toPort = 65535
			}
			portRange := fmt.Sprintf("%v-%v", fromPort, toPort)
			remotes := []string{}
			for _, pair := range r.rule.UserIdGroupPairs {
				remotes = append(remotes, common.GetUUID(a.getStringPointerValue(pair.GroupId), uuid.Nil))
			}
			ipSlice := []string{}
			for _, ip4 := range r.rule.IpRanges {
				ipSlice = append(ipSlice, a.getStringPointerValue(ip4.CidrIp))
			}
			for _, ip6 := range r.rule.Ipv6Ranges {
				ipSlice = append(ipSlice, a.getStringPointerValue(ip6.CidrIpv6))
			}
			// 对该字段进行排序来保证每次生成的lcuuid相同
			sort.Strings(ipSlice)
			remotes = append(remotes, strings.Join(ipSlice, ","))
			for _, remote := range remotes {
				if remote == "" {
					continue
				}
				local := common.SECURITY_GROUP_RULE_IPV4_CIDR
				if r.direction == common.SECURITY_GROUP_RULE_INGRESS {
					local, remote = remote, local
				}
				sgRules = append(sgRules, model.SecurityGroupRule{
					Lcuuid:              common.GetUUID(strconv.Itoa(int(r.direction))+sgGroupID+portRange+protocol+remote+local, uuid.Nil),
					SecurityGroupLcuuid: sgLcuuid,
					Direction:           r.direction,
					EtherType:           common.SECURITY_GROUP_RULE_IPV4,
					Protocol:            protocol,
					LocalPortRange:      "0-65535",
					RemotePortRange:     portRange,
					Local:               local,
					Remote:              remote,
					Priority:            r.priority,
					Action:              common.SECURITY_GROUP_RULE_ACCEPT,
				})
			}
		}

		for _, d := range []int{common.SECURITY_GROUP_RULE_INGRESS, common.SECURITY_GROUP_RULE_EGRESS} {
			for _, e := range []int{common.SECURITY_GROUP_RULE_IPV4, common.SECURITY_GROUP_RULE_IPV6} {
				remote := common.SECURITY_GROUP_RULE_IPV6_CIDR
				if e == common.SECURITY_GROUP_RULE_IPV4 {
					remote = common.SECURITY_GROUP_RULE_IPV4_CIDR
				}
				sgRules = append(sgRules, model.SecurityGroupRule{
					Lcuuid:              common.GetUUID(sgLcuuid+strconv.Itoa(d)+remote, uuid.Nil),
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
