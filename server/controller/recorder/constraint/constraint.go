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

// recorder包中使用到的泛型约束
package constraint

import (
	cloudmodel "github.com/deepflowio/deepflow/server/controller/cloud/model"
	"github.com/deepflowio/deepflow/server/controller/db/mysql"
	"github.com/deepflowio/deepflow/server/controller/recorder/cache"
)

// 资源的MySQL orm对象
type MySQLModel interface {
	mysql.Region | mysql.AZ | mysql.SubDomain | mysql.Host | mysql.VM |
		mysql.VPC | mysql.Network | mysql.Subnet | mysql.VRouter | mysql.RoutingTable |
		mysql.DHCPPort | mysql.VInterface | mysql.WANIP | mysql.LANIP | mysql.FloatingIP |
		mysql.SecurityGroup | mysql.SecurityGroupRule | mysql.VMSecurityGroup |
		mysql.NATGateway | mysql.NATRule | mysql.NATVMConnection | mysql.LB |
		mysql.LBListener | mysql.LBTargetServer | mysql.LBVMConnection | mysql.CEN |
		mysql.PeerConnection | mysql.RDSInstance | mysql.RedisInstance | mysql.PodCluster |
		mysql.PodNode | mysql.VMPodNodeConnection | mysql.PodNamespace | mysql.PodIngress |
		mysql.PodIngressRule | mysql.PodIngressRuleBackend | mysql.PodService |
		mysql.PodServicePort | mysql.PodGroup | mysql.PodGroupPort | mysql.PodReplicaSet |
		mysql.Pod | mysql.Process

	GetLcuuid() string
	GetID() int
}

// 资源的原始数据结构
type CloudModel interface {
	cloudmodel.Region | cloudmodel.AZ | cloudmodel.SubDomain | cloudmodel.Host | cloudmodel.VM |
		cloudmodel.VPC | cloudmodel.Network | cloudmodel.Subnet | cloudmodel.VRouter | cloudmodel.RoutingTable |
		cloudmodel.DHCPPort | cloudmodel.VInterface | cloudmodel.IP | cloudmodel.FloatingIP |
		cloudmodel.SecurityGroup | cloudmodel.SecurityGroupRule | cloudmodel.VMSecurityGroup |
		cloudmodel.NATGateway | cloudmodel.NATRule | cloudmodel.NATVMConnection | cloudmodel.LB |
		cloudmodel.LBListener | cloudmodel.LBTargetServer | cloudmodel.LBVMConnection | cloudmodel.CEN |
		cloudmodel.PeerConnection | cloudmodel.RDSInstance | cloudmodel.RedisInstance | cloudmodel.PodCluster |
		cloudmodel.PodNode | cloudmodel.VMPodNodeConnection | cloudmodel.PodNamespace | cloudmodel.PodIngress |
		cloudmodel.PodIngressRule | cloudmodel.PodIngressRuleBackend | cloudmodel.PodService |
		cloudmodel.PodServicePort | cloudmodel.PodGroup | cloudmodel.PodGroupPort | cloudmodel.PodReplicaSet |
		cloudmodel.Pod | cloudmodel.Process
}

// 资源用于比对的缓存对象
type DiffBase[MT MySQLModel] interface {
	*cache.Region | *cache.AZ | *cache.SubDomain | *cache.Host | *cache.VM |
		*cache.VPC | *cache.Network | *cache.Subnet | *cache.VRouter | *cache.RoutingTable |
		*cache.DHCPPort | *cache.VInterface | *cache.WANIP | *cache.LANIP | *cache.FloatingIP |
		*cache.SecurityGroup | *cache.SecurityGroupRule | *cache.VMSecurityGroup |
		*cache.NATGateway | *cache.NATRule | *cache.NATVMConnection | *cache.LB |
		*cache.LBListener | *cache.LBTargetServer | *cache.LBVMConnection | *cache.CEN |
		*cache.PeerConnection | *cache.RDSInstance | *cache.RedisInstance | *cache.PodCluster |
		*cache.PodNode | *cache.VMPodNodeConnection | *cache.PodNamespace | *cache.PodIngress |
		*cache.PodIngressRule | *cache.PodIngressRuleBackend | *cache.PodService |
		*cache.PodServicePort | *cache.PodGroup | *cache.PodGroupPort | *cache.PodReplicaSet |
		*cache.Pod | *cache.Process

	GetSequence() int
	SetSequence(sequence int)
	GetLcuuid() string
}

// 软删除资源的MySQL orm对象
type MySQLSoftDeleteModel interface {
	mysql.Region | mysql.AZ | mysql.Host | mysql.VM | mysql.VPC | mysql.Network |
		mysql.VRouter | mysql.DHCPPort | mysql.SecurityGroup | mysql.NATGateway |
		mysql.LB | mysql.LBListener | mysql.CEN | mysql.PeerConnection | mysql.RDSInstance |
		mysql.RedisInstance | mysql.PodCluster | mysql.PodNode | mysql.PodNamespace |
		mysql.PodIngress | mysql.PodService | mysql.PodGroup | mysql.PodReplicaSet | mysql.Pod |
		mysql.Process
}
