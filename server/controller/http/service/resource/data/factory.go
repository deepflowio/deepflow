/**
 * Copyright (c) 2023 Yunshan Networks
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

package data

import (
	"github.com/deepflowio/deepflow/server/controller/common"
	"github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/controller/db/redis"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/mysql"
	mysqldp "github.com/deepflowio/deepflow/server/controller/http/service/resource/data/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/service/resource/data/provider"
	redisdp "github.com/deepflowio/deepflow/server/controller/http/service/resource/data/redis"
)

type RequiredConfigs struct {
	Redis      redis.Config
	WebService config.DFWebService
}

// GetDataProvider determines which resource uses which type of data provider
func GetDataProvider(resourceType string, cfg *RequiredConfigs) provider.DataProvider {
	switch resourceType {
	case common.RESOURCE_TYPE_REGION_EN:
		return mysql.NewRegion(cfg.WebService)
	case common.RESOURCE_TYPE_AZ_EN:
		return mysqldp.NewAZ(cfg.WebService)
	case common.RESOURCE_TYPE_HOST_EN:
		return mysqldp.NewHost()
	case common.RESOURCE_TYPE_VM_EN:
		return redisdp.GetVM(cfg.Redis)
	case common.RESOURCE_TYPE_VINTERFACE_EN:
		return redisdp.GetVInterface(cfg.Redis)
	case common.RESOURCE_TYPE_SECURITY_GROUP_EN:
		return mysql.NewSecurityGroup()
	case common.RESOURCE_TYPE_SECURITY_GROUP_RULE_EN:
		return mysql.NewSecurityGroupRule()
	case common.RESOURCE_TYPE_NAT_GATEWAY_EN:
		return mysql.NewNATGateway()
	case common.RESOURCE_TYPE_NAT_RULE_EN:
		return mysql.NewNATRule()
	case common.RESOURCE_TYPE_LB_EN:
		return mysql.NewLB()
	case common.RESOURCE_TYPE_LB_LISTENER_EN:
		return mysql.NewLBListener()
	case common.RESOURCE_TYPE_LB_RULE_EN:
		return mysql.NewLBRule()
	case common.RESOURCE_TYPE_PEER_CONNECTION_EN:
		return mysql.NewPeerConnection()
	case common.RESOURCE_TYPE_CEN_EN:
		return mysql.NewCEN()
	case common.RESOURCE_TYPE_POD_EN:
		return redisdp.GetPod(cfg.Redis)
	case common.RESOURCE_TYPE_POD_GROUP_EN:
		return redisdp.GetPodGroup(cfg.Redis)
	case common.RESOURCE_TYPE_POD_GROUP_PORT_EN:
		return mysqldp.NewPodGroupPort()
	case common.RESOURCE_TYPE_POD_REPLICA_SET_EN:
		return redisdp.GetPodReplicaSet(cfg.Redis)
	case common.RESOURCE_TYPE_POD_SERVICE_EN:
		return redisdp.GetPodSerivce(cfg.Redis)
	case common.RESOURCE_TYPE_POD_SERVICE_PORT_EN:
		return mysqldp.NewPodServicePort()
	case common.RESOURCE_TYPE_POD_INGRESS_EN:
		return redisdp.GetPodIngress(cfg.Redis)
	case common.RESOURCE_TYPE_POD_INGRESS_RULE_EN:
		return mysql.NewPodIngressRule()
	case common.RESOURCE_TYPE_POD_NODE_EN:
		return redisdp.GetPodNode(cfg.Redis)
	case common.RESOURCE_TYPE_POD_CLUSTER_EN:
		return redisdp.GetPodCluster(cfg.Redis)

	default:
		return nil
	}
}
