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
	"encoding/json"
	"time"

	"github.com/baidubce/bce-sdk-go/services/cce"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (b *BaiduBce) getSubDomains(region model.Region, vpcIdToLcuuid map[string]string) ([]model.SubDomain, error) {
	var retSubDomains []model.SubDomain

	log.Debug("get sub_domains starting")

	cceClient, _ := cce.NewClient(b.secretID, b.secretKey, "cce."+b.endpoint)
	cceClient.Config.ConnectionTimeoutInMillis = b.httpTimeout * 1000
	marker := ""
	args := &cce.ListClusterArgs{}
	results := make([]*cce.ListClusterResult, 0)
	for {
		args.Marker = marker
		startTime := time.Now()
		result, err := cceClient.ListClusters(args)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		b.cloudStatsd.RefreshAPIMoniter("ListClusters", len(result.Clusters), startTime)
		results = append(results, result)
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}

	b.debugger.WriteJson("ListClusters", " ", structToJson(results))
	for _, r := range results {
		for _, cluster := range r.Clusters {
			vpcLcuuid, ok := vpcIdToLcuuid[cluster.VpcId]
			if !ok {
				log.Debugf("cluster (%s) vpc (%s) not found", cluster.ClusterUuid, cluster.VpcId)
				continue
			}

			config := map[string]interface{}{
				"vpc_uuid":                   vpcLcuuid,
				"cluster_id":                 cluster.ClusterUuid,
				"port_name_regex":            common.DEFAULT_PORT_NAME_REGEX,
				"vtap_id":                    "",
				"controller_ip":              "",
				"region_uuid":                region.Lcuuid,
				"pod_net_ipv4_cidr_max_mask": common.K8S_POD_IPV4_NETMASK,
				"pod_net_ipv6_cidr_max_mask": common.K8S_POD_IPV6_NETMASK,
			}
			configJson, _ := json.Marshal(config)
			retSubDomains = append(retSubDomains, model.SubDomain{
				Lcuuid:      common.GenerateUUID(cluster.ClusterUuid),
				Name:        cluster.ClusterName,
				DisplayName: cluster.ClusterUuid,
				ClusterID:   cluster.ClusterUuid,
				VpcUUID:     vpcLcuuid,
				Config:      string(configJson),
			})
		}
	}
	log.Debug("get sub_domains complete")
	return retSubDomains, nil
}
