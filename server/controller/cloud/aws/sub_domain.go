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

package aws

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
)

func (a *Aws) getSubDomains(region string) ([]model.SubDomain, error) {
	var retSubDomains []model.SubDomain

	log.Debug("get sub_domains starting", logger.NewORGPrefix(a.orgID))

	eksClientConfig, err := config.LoadDefaultConfig(context.TODO(), a.credential, config.WithRegion(region), config.WithHTTPClient(a.httpClient))
	if err != nil {
		log.Error(err.Error(), logger.NewORGPrefix(a.orgID))
		return []model.SubDomain{}, err
	}

	var retClusterNames []string
	var nextToken string
	var maxResults int32 = 100
	for {
		var input *eks.ListClustersInput
		if nextToken == "" {
			input = &eks.ListClustersInput{MaxResults: &maxResults}
		} else {
			input = &eks.ListClustersInput{MaxResults: &maxResults, NextToken: &nextToken}
		}
		result, err := eks.NewFromConfig(eksClientConfig).ListClusters(context.TODO(), input)
		if err != nil {
			log.Errorf("subdomains request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
			return []model.SubDomain{}, err
		}
		retClusterNames = append(retClusterNames, result.Clusters...)
		if result.NextToken == nil {
			break
		}
		nextToken = *result.NextToken
	}

	for _, name := range retClusterNames {
		clusterName := name
		clusterInput := &eks.DescribeClusterInput{Name: &clusterName}
		clusterResult, err := eks.NewFromConfig(eksClientConfig).DescribeCluster(context.TODO(), clusterInput)
		if err != nil {
			log.Errorf("subdomain info request aws api error: (%s)", err.Error(), logger.NewORGPrefix(a.orgID))
			return []model.SubDomain{}, err
		}

		vpcID := a.getStringPointerValue(clusterResult.Cluster.ResourcesVpcConfig.VpcId)
		vpcLcuuid, ok := a.vpcIDToLcuuid[vpcID]
		if vpcID == "" || !ok {
			log.Debugf("cluster (%s) vpc (%s) not found", name, vpcID, logger.NewORGPrefix(a.orgID))
			continue
		}
		config := map[string]interface{}{
			"cluster_id":                 name,
			"region_uuid":                a.regionLcuuid,
			"vpc_uuid":                   vpcLcuuid,
			"port_name_regex":            common.DEFAULT_PORT_NAME_REGEX,
			"pod_net_ipv4_cidr_max_mask": common.K8S_POD_IPV4_NETMASK,
			"pod_net_ipv6_cidr_max_mask": common.K8S_POD_IPV6_NETMASK,
		}
		configJson, _ := json.Marshal(config)
		retSubDomains = append(retSubDomains, model.SubDomain{
			TeamID:      a.teamID,
			Lcuuid:      common.GetUUIDByOrgID(a.orgID, name),
			Name:        name,
			DisplayName: name,
			ClusterID:   name,
			VpcUUID:     vpcLcuuid,
			Config:      string(configJson),
		})
	}
	log.Debug("get sub_domains complete", logger.NewORGPrefix(a.orgID))
	return retSubDomains, nil
}
