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

package constraint

import (
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/http/model"
)

// 各资源可支持的 query 字段定义
type QueryModel interface {
	model.AZQuery | model.HostQuery | model.VMQuery | model.VInterfaceQuery |
		model.SecurityGroupQuery | model.SecurityGroupRuleQuery | model.NATGatewayQuery | model.NATRuleQuery |
		model.PodQuery | model.PodReplicaSetQuery | model.PodGroupQuery | model.PodGroupPortQuery |
		model.PodServiceQuery | model.PodServicePortQuery | model.PodIngressQuery | model.PodIngressRuleQuery |
		model.PodNodeQuery | model.PodNamespaceQuery | model.PodClusterQuery |
		model.IPQuery | model.DHCPPortQuery | model.VRouterQuery | model.RoutingTableQuery |
		model.NetworkQuery | model.VPCQuery

	GetIncludedFields() []string
	GetUserID() int
	GetFilterConditions() map[string]interface{}
}

// 各资源需要用于构建 redis 缓存 key 的 query 字段定义
type QueryStoredInRedisModel interface {
	model.AZQueryStoredInRedis | model.HostQueryStoredInRedis | model.VMQueryStoredInRedis | model.VInterfaceQueryStoredInRedis |
		model.PodQueryStoredInRedis | model.PodReplicaSetQueryStoredInRedis |
		model.PodGroupQueryStoredInRedis | model.PodGroupPortQueryStoredInRedis | model.PodServiceQueryStoredInRedis |
		model.PodServicePortQueryStoredInRedis | model.PodIngressQueryStoredInRedis | model.PodIngressRuleQueryStoredInRedis |
		model.PodNodeQueryStoredInRedis | model.PodNamespaceQueryStoredInRedis | model.PodClusterQueryStoredInRedis |
		model.IPQueryStoredInRedis | model.DHCPPortQueryStoredInRedis | model.VRouterQueryStoredInRedis | model.RoutingTableQuery |
		model.NetworkQueryStoredInRedis | model.VPCQueryStoredInRedis

	GetIncludedFields() []string
	GetUserID() int
	GetFilterConditions() map[string]interface{}
}

type MySQLModel interface {
	mysql.Domain | mysql.Region | mysql.AZ | mysql.SubDomain | mysql.Host | mysql.VM |
		mysql.VPC | mysql.Network | mysql.Subnet | mysql.VRouter | mysql.RoutingTable |
		mysql.DHCPPort | mysql.VInterface | mysql.WANIP | mysql.LANIP | mysql.FloatingIP |
		mysql.SecurityGroup | mysql.SecurityGroupRule | mysql.VMSecurityGroup |
		mysql.NATGateway | mysql.NATRule | mysql.NATVMConnection | mysql.LB |
		mysql.LBListener | mysql.LBTargetServer | mysql.LBVMConnection | mysql.CEN |
		mysql.PeerConnection | mysql.RDSInstance | mysql.RedisInstance | mysql.PodCluster |
		mysql.PodNode | mysql.VMPodNodeConnection | mysql.PodNamespace | mysql.PodIngress |
		mysql.PodIngressRule | mysql.PodIngressRuleBackend | mysql.PodService |
		mysql.PodServicePort | mysql.PodGroup | mysql.PodGroupPort | mysql.PodReplicaSet |
		mysql.Pod | mysql.Process | mysql.PrometheusTarget
}
