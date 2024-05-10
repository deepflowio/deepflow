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
	"encoding/json"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/cs"
	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
)

func (a *Aliyun) getSubDomains(region model.Region) ([]model.SubDomain, error) {
	var retSubDomains []model.SubDomain

	log.Debug("get sub_domains starting")
	request := cs.CreateDescribeClustersV1Request()
	response, err := a.getSubDomainResponse(region.Label, request)
	if err != nil {
		log.Error(err)
		return retSubDomains, err
	}

	for _, retArry := range response {
		for c := range retArry.MustArray() {
			cluster := retArry.GetIndex(c)
			clusterID := cluster.Get("cluster_id").MustString()
			vpcID := cluster.Get("vpc_id").MustString()
			vpcLcuuid, ok := a.vpcIDToLcuuids[vpcID]
			if vpcID == "" || !ok {
				log.Debugf("cluster (%s) vpc (%s) not found", clusterID, vpcID)
				continue
			}
			config := map[string]interface{}{
				"cluster_id":                 clusterID,
				"region_uuid":                a.getRegionLcuuid(region.Lcuuid),
				"vpc_uuid":                   vpcLcuuid,
				"port_name_regex":            common.DEFAULT_PORT_NAME_REGEX,
				"pod_net_ipv4_cidr_max_mask": common.K8S_POD_IPV4_NETMASK,
				"pod_net_ipv6_cidr_max_mask": common.K8S_POD_IPV6_NETMASK,
			}
			configJson, _ := json.Marshal(config)
			retSubDomains = append(retSubDomains, model.SubDomain{
				TeamID:      a.teamID,
				Lcuuid:      common.GenerateUUIDByOrgID(a.orgID, clusterID),
				Name:        cluster.Get("name").MustString(),
				DisplayName: clusterID,
				ClusterID:   clusterID,
				VpcUUID:     vpcLcuuid,
				Config:      string(configJson),
			})
		}
	}
	log.Debug("get sub_domains complete")
	return retSubDomains, nil
}
