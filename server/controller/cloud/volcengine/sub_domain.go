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

package volcengine

import (
	"encoding/json"

	"github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/libs/logger"
	"github.com/volcengine/volcengine-go-sdk/service/vke"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

func (v *VolcEngine) getSubDomains(sess *session.Session) []model.SubDomain {
	log.Debug("get sub_domains starting", logger.NewORGPrefix(v.orgID))
	var subDomains []model.SubDomain

	var retSubDomains []*vke.ItemForListClustersOutput
	var pageNumber, pageSize int32 = 1, 100
	for {
		input := &vke.ListClustersInput{PageNumber: &pageNumber, PageSize: &pageSize}
		result, err := vke.New(sess).ListClusters(input)
		if err != nil {
			log.Warningf("request volcengine (vke.ListClusters) api error: (%s)", err.Error(), logger.NewORGPrefix(v.orgID))
			return []model.SubDomain{}
		}
		retSubDomains = append(retSubDomains, result.Items...)
		if len(result.Items) < int(pageSize) {
			break
		}
		pageSize += 1
	}

	for _, retSubDomain := range retSubDomains {
		if retSubDomain == nil || retSubDomain.ClusterConfig == nil {
			continue
		}
		clusterID := v.getStringPointerValue(retSubDomain.Id)
		vpcLcuuid := common.GetUUIDByOrgID(v.orgID, v.getStringPointerValue(retSubDomain.ClusterConfig.VpcId))
		config := map[string]interface{}{
			"cluster_id":                 clusterID,
			"region_uuid":                v.regionLcuuid,
			"vpc_uuid":                   vpcLcuuid,
			"port_name_regex":            common.DEFAULT_PORT_NAME_REGEX,
			"pod_net_ipv4_cidr_max_mask": common.K8S_POD_IPV4_NETMASK,
			"pod_net_ipv6_cidr_max_mask": common.K8S_POD_IPV6_NETMASK,
		}
		configJson, _ := json.Marshal(config)
		subDomains = append(subDomains, model.SubDomain{
			TeamID:      v.teamID,
			Lcuuid:      common.GetUUIDByOrgID(v.orgID, clusterID),
			Name:        v.getStringPointerValue(retSubDomain.Name),
			DisplayName: clusterID,
			ClusterID:   clusterID,
			VpcUUID:     vpcLcuuid,
			Config:      string(configJson),
		})
	}
	log.Debug("get sub_domains complete", logger.NewORGPrefix(v.orgID))
	return subDomains
}
